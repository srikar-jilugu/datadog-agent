// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

package probe

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"path"
	"strings"
	"time"

	"github.com/DataDog/datadog-agent/pkg/security/probe/managerhelper"

	manager "github.com/DataDog/ebpf-manager"
	"github.com/cilium/ebpf"

	"github.com/DataDog/datadog-agent/pkg/security/probe/erpc"
	"github.com/DataDog/datadog-agent/pkg/security/probe/monitors/discarder"
	"github.com/DataDog/datadog-agent/pkg/security/resolvers/dentry"
	"github.com/DataDog/datadog-agent/pkg/security/secl/compiler/eval"
	"github.com/DataDog/datadog-agent/pkg/security/secl/model"
	"github.com/DataDog/datadog-agent/pkg/security/secl/rules"
	"github.com/DataDog/datadog-agent/pkg/security/seclog"
	"github.com/DataDog/datadog-agent/pkg/security/utils"
)

const (
	// DiscardRetention time a discard is retained but not discarding. This avoid race for pending event is userspace
	// pipeline for already deleted file in kernel space.
	DiscardRetention = 5 * time.Second

	// maxParentDiscarderDepth defines the maximum parent depth to find parent discarders
	// the eBPF part need to be adapted accordingly
	maxParentDiscarderDepth = 3

	// allEventTypes is a mask to match all the events
	allEventTypes = math.MaxUint32 //nolint:deadcode,unused

	// inode/mountid that won't be resubmitted
	maxRecentlyAddedCacheSize = uint64(64)
)

var (
	// DiscarderConstants ebpf constants
	DiscarderConstants = []manager.ConstantEditor{
		{
			Name:  "discarder_retention",
			Value: uint64(DiscardRetention.Nanoseconds()),
		},
	}

	// recentlyAddedTimeout do not add twice the same discarder in 2sec
	recentlyAddedTimeout = uint64(2 * time.Second.Nanoseconds())
)

type discarderHandler func(rs *rules.RuleSet, event *model.Event, probe *EBPFProbe, discarder Discarder) (bool, error)

var (
	allDiscarderHandlers = make(map[eval.Field]discarderHandler)
	eventZeroDiscarder   = model.NewFakeEvent()
)

var dnsMask uint16

// bumpDiscardersRevision sends an eRPC request to bump the discarders revisionr
func bumpDiscardersRevision(e *erpc.ERPC) error {
	req := erpc.NewERPCRequest(erpc.BumpDiscardersRevision)
	return e.Request(req)
}

func marshalDiscardHeader(req *erpc.Request, eventType model.EventType, timeout uint64) int {
	binary.NativeEndian.PutUint64(req.Data[0:8], uint64(eventType))
	binary.NativeEndian.PutUint64(req.Data[8:16], timeout)

	return 16
}

// InodeDiscarderMapEntry describes a map entry
type InodeDiscarderMapEntry struct {
	PathKey model.PathKey
	IsLeaf  uint32
	Padding uint32
}

// InodeDiscarderEntry describes a map entry
type InodeDiscarderEntry struct {
	Inode     uint64
	MountID   uint32
	Timestamp uint64
}

// InodeDiscarderParams describes a map value
type InodeDiscarderParams struct {
	DiscarderParams `yaml:"params"`
	Revision        uint32
}

// DiscarderParams describes a map value
type DiscarderParams struct {
	EventMask  uint64                                                                   `yaml:"event_mask"`
	Timestamps [model.LastDiscarderEventType + 1 - model.FirstDiscarderEventType]uint64 `yaml:"-"`
	ExpireAt   uint64                                                                   `yaml:"expire_at"`
	IsRetained uint32                                                                   `yaml:"is_retained"`
	Revision   uint32
}

func recentlyAddedIndex(mountID uint32, inode uint64) uint64 {
	return (uint64(mountID)<<32 | inode) % maxRecentlyAddedCacheSize
}

// inodeDiscarders is used to issue eRPC discarder requests
type inodeDiscarders struct {
	erpc           *erpc.ERPC
	dentryResolver *dentry.Resolver
	rs             *rules.RuleSet
	discarderEvent *model.Event
	evalCtx        *eval.Context

	// parentDiscarderFncs holds parent discarder functions per depth
	parentDiscarderFncs [maxParentDiscarderDepth]map[eval.Field]func(dirname string) (bool, error)

	recentlyAddedEntries [maxRecentlyAddedCacheSize]InodeDiscarderEntry
}

func newInodeDiscarders(erpc *erpc.ERPC, dentryResolver *dentry.Resolver) *inodeDiscarders {
	event := *eventZeroDiscarder

	ctx := eval.NewContext(&event)

	id := &inodeDiscarders{
		erpc:           erpc,
		dentryResolver: dentryResolver,
		discarderEvent: &event,
		evalCtx:        ctx,
	}

	id.initParentDiscarderFncs()

	return id
}

func (id *inodeDiscarders) isRecentlyAdded(mountID uint32, inode uint64, timestamp uint64) bool {
	entry := id.recentlyAddedEntries[recentlyAddedIndex(mountID, inode)]

	var delta uint64
	if timestamp > entry.Timestamp {
		delta = timestamp - entry.Timestamp
	} else {
		delta = entry.Timestamp - timestamp
	}

	return entry.MountID == mountID && entry.Inode == inode && delta < recentlyAddedTimeout
}

func (id *inodeDiscarders) recentlyAdded(mountID uint32, inode uint64, timestamp uint64) {
	entry := &id.recentlyAddedEntries[recentlyAddedIndex(mountID, inode)]
	entry.MountID = mountID
	entry.Inode = inode
	entry.Timestamp = timestamp
}

func (id *inodeDiscarders) discardInode(req *erpc.Request, eventType model.EventType, mountID uint32, inode uint64, isLeaf bool) error {
	var isLeafInt uint32
	if isLeaf {
		isLeafInt = 1
	}

	req.OP = erpc.DiscardInodeOp

	offset := marshalDiscardHeader(req, eventType, 0)
	binary.NativeEndian.PutUint64(req.Data[offset:offset+8], inode)
	binary.NativeEndian.PutUint32(req.Data[offset+8:offset+12], mountID)
	binary.NativeEndian.PutUint32(req.Data[offset+12:offset+16], isLeafInt)

	return id.erpc.Request(req)
}

// use a faster version of path.Dir which adds some sanity checks not required here
func dirname(filename string) string {
	if len(filename) == 0 {
		return "/"
	}

	i := len(filename) - 1
	for i >= 0 && filename[i] != '/' {
		i--
	}

	if filename == "/" {
		return filename
	}

	if i <= 0 {
		return "/"
	}

	return filename[:i]
}

func getParent(filename string, depth int) string {
	for ; depth > 0; depth-- {
		filename = dirname(filename)
	}

	return filename
}

func (id *inodeDiscarders) getParentDiscarderFnc(rs *rules.RuleSet, eventType model.EventType, field eval.Field, depth int) (func(dirname string) (bool, error), error) {
	fnc, exists := id.parentDiscarderFncs[depth-1][field]
	if exists {
		return fnc, nil
	}

	bucket := rs.GetBucket(eventType.String())
	if bucket == nil {
		return nil, nil
	}

	if _, _, _, err := id.discarderEvent.GetFieldMetadata(field); err != nil {
		return nil, err
	}

	if !strings.HasSuffix(field, model.PathSuffix) {
		return nil, errors.New("path suffix not found")
	}

	basenameField := strings.Replace(field, model.PathSuffix, model.NameSuffix, 1)
	if _, _, _, err := id.discarderEvent.GetFieldMetadata(basenameField); err != nil {
		return nil, err
	}

	var basenameRules []*rules.Rule

	var isDiscarderFnc func(dirname string) (bool, bool, error)
	var isDiscarderFncs []func(dirname string) (bool, bool, error)

	for _, rule := range bucket.GetRules() {
		// ensure we don't push parent discarder if there is another rule relying on the parent path

		// first case: rule contains a filename field
		// ex: rule		open.file.path == "/etc/passwd"
		//     discarder /etc/fstab
		// /etc/fstab is a discarder but not the parent

		// second case: rule doesn't contain a filename field but a basename field
		// ex: rule	 	open.file.name == "conf.d"
		//     discarder /etc/conf.d/httpd.conf
		// /etc/conf.d/httpd.conf is a discarder but not the parent

		// check filename
		if values := rule.GetFieldValues(field); len(values) > 0 {
			for _, value := range values {
				if value.Type == eval.GlobValueType {
					glob, err := eval.NewGlob(value.Value.(string), false, false)
					if err != nil {
						return nil, fmt.Errorf("unexpected glob `%v`: %w", value.Value, err)
					}

					isDiscarderFnc = func(dirname string) (bool, bool, error) {
						return !glob.Contains(dirname), false, nil
					}
				} else if value.Type == eval.ScalarValueType {
					str := value.Value.(string)
					isDiscarderFnc = func(dirname string) (bool, bool, error) {
						return !strings.HasPrefix(str, dirname), false, nil
					}
				} else {
					// regex are not currently supported on path, see ValidateFields
					isDiscarderFnc = func(_ string) (bool, bool, error) {
						return false, false, nil
					}
				}

				isDiscarderFncs = append(isDiscarderFncs, isDiscarderFnc)
			}
		}

		// collect all the rule on which we need to check the parent discarder found
		if values := rule.GetFieldValues(basenameField); len(values) > 0 {
			basenameRules = append(basenameRules, rule)
		}
	}

	// basename check, the goal is to ensure there is no dirname(parent) that matches a .file.name rule
	isDiscarderFnc = func(dirname string) (bool, bool, error) {
		if err := id.discarderEvent.SetFieldValue(basenameField, path.Base(dirname)); err != nil {
			return false, false, err
		}

		if len(basenameRules) > 0 {
			if isDiscarder, _, _ := rules.IsDiscarder(id.evalCtx, basenameField, basenameRules); !isDiscarder {
				return false, true, nil
			}
		}

		return true, true, nil
	}
	isDiscarderFncs = append(isDiscarderFncs, isDiscarderFnc)

	fnc = func(dirname string) (bool, error) {
		var result, altered bool
		var err error

		defer func() {
			if altered {
				*id.discarderEvent = *eventZeroDiscarder
			}
		}()

		for _, fnc := range isDiscarderFncs {
			result, altered, err = fnc(dirname)
			if !result {
				return false, err
			}
		}

		return len(isDiscarderFncs) > 0, nil
	}
	id.parentDiscarderFncs[depth-1][field] = fnc

	return fnc, nil
}

func (id *inodeDiscarders) initParentDiscarderFncs() {
	for i := range id.parentDiscarderFncs {
		id.parentDiscarderFncs[i] = make(map[eval.Field]func(dirname string) (bool, error))
	}
}

// onRuleSetChanged if the ruleset changed we need to flush all the previous functions
func (id *inodeDiscarders) onRuleSetChanged(rs *rules.RuleSet) {
	id.initParentDiscarderFncs()
	id.rs = rs
}

func (id *inodeDiscarders) isParentPathDiscarder(rs *rules.RuleSet, eventType model.EventType, field eval.Field, filename string, depth int) (bool, error) {
	if id.rs != rs {
		id.onRuleSetChanged(rs)
	}

	fnc, err := id.getParentDiscarderFnc(rs, eventType, field, depth)
	if fnc == nil || err != nil {
		return false, err
	}

	dirname := getParent(filename, depth)
	if dirname == "/" {
		// never discard /
		return false, nil
	}

	found, err := fnc(dirname)
	if !found || err != nil {
		return false, err
	}

	seclog.Tracef("`%s` discovered as parent discarder for `%s`", dirname, field)

	return true, nil
}

func (id *inodeDiscarders) discardParentInode(req *erpc.Request, rs *rules.RuleSet, eventType model.EventType, field eval.Field, filename string, pathKey model.PathKey, timestamp uint64) (bool, uint32, uint64, error) {
	var discarderDepth int
	var isDiscarder bool
	var err error

	for depth := maxParentDiscarderDepth; depth > 0; depth-- {
		if isDiscarder, err = id.isParentPathDiscarder(rs, eventType, field, filename, depth); isDiscarder {
			discarderDepth = depth
			break
		}
	}

	if err != nil || discarderDepth == 0 {
		return false, 0, 0, err
	}

	parentKey := pathKey

	for i := 0; i < discarderDepth; i++ {
		key, err := id.dentryResolver.GetParent(parentKey)
		if err != nil || model.IsFakeInode(pathKey.Inode) {
			if i == 0 {
				return false, 0, 0, err
			}
			break
		}
		parentKey = key
	}

	// do not insert multiple time the same discarder
	if id.isRecentlyAdded(parentKey.MountID, parentKey.Inode, timestamp) {
		return false, 0, 0, nil
	}

	if err := id.discardInode(req, eventType, parentKey.MountID, parentKey.Inode, false); err != nil {
		return false, 0, 0, err
	}

	id.recentlyAdded(parentKey.MountID, parentKey.Inode, timestamp)

	return true, parentKey.MountID, parentKey.Inode, nil
}

// function used to retrieve discarder information, *.file.path, FileEvent, file deleted
type inodeEventGetter = func(event *model.Event) (eval.Field, *model.FileEvent, bool)

func filenameDiscarderWrapper(eventType model.EventType, getter inodeEventGetter) discarderHandler {
	return func(rs *rules.RuleSet, event *model.Event, probe *EBPFProbe, _ Discarder) (bool, error) {
		field, fileEvent, isDeleted := getter(event)

		if fileEvent.PathResolutionError != nil {
			return false, fileEvent.PathResolutionError
		}

		value, err := event.GetFieldValue(field)
		if err != nil {
			return false, err
		}
		filename := value.(string)

		if filename == "" {
			return false, nil
		}

		if isInvalidDiscarder(field, filename) {
			return false, nil
		}

		isDiscarded, _, parentInode, err := probe.inodeDiscarders.discardParentInode(probe.erpcRequest, rs, eventType, field, filename, fileEvent.PathKey, event.TimestampRaw)
		if !isDiscarded && !isDeleted && err == nil {
			if !model.IsFakeInode(fileEvent.PathKey.Inode) {
				seclog.Tracef("Apply `%s.file.path` inode discarder for event `%s`, inode: %d(%s)", eventType, eventType, fileEvent.PathKey.Inode, filename)

				// not able to discard the parent then only discard the filename
				_ = probe.inodeDiscarders.discardInode(probe.erpcRequest, eventType, fileEvent.PathKey.MountID, fileEvent.PathKey.Inode, true)
			}
		} else if !isDeleted {
			seclog.Tracef("Apply `%s.file.path` parent inode discarder for event `%s`, inode: %d(%s)", eventType, eventType, parentInode, filename)
		}

		if err != nil {
			err = fmt.Errorf("unable to set inode discarders for `%s` for event `%s`, inode: %d: %w", filename, eventType, parentInode, err)
		}

		return true, err
	}
}

// isInvalidDiscarder returns whether the given value is a valid discarder for the given field
func isInvalidDiscarder(field eval.Field, value string) bool {
	return (strings.HasSuffix(field, ".file.path") || strings.HasSuffix(field, ".file.destination.path")) && value == ""
}

// InodeDiscarderDump describes a dump of an inode discarder
type InodeDiscarderDump struct {
	Index                int `yaml:"index"`
	InodeDiscarderParams `yaml:"value"`
	FilePath             string `yaml:"path"`
	Inode                uint64
	MountID              uint32 `yaml:"mount_id"`
}

// DiscardersDump describes a dump of discarders
type DiscardersDump struct {
	Date   time.Time                  `yaml:"date"`
	Inodes []InodeDiscarderDump       `yaml:"inodes"`
	Stats  map[string]discarder.Stats `yaml:"stats"`
}

func dumpInodeDiscarders(resolver *dentry.Resolver, inodeMap *ebpf.Map) ([]InodeDiscarderDump, error) {
	var dumps []InodeDiscarderDump

	info, err := inodeMap.Info()
	if err != nil {
		return nil, fmt.Errorf("could not get info about inode discarders: %w", err)
	}

	var (
		count       int
		inodeEntry  InodeDiscarderMapEntry
		inodeParams InodeDiscarderParams
	)

	for entries := inodeMap.Iterate(); entries.Next(&inodeEntry, &inodeParams); {
		record := InodeDiscarderDump{
			Index:                count,
			InodeDiscarderParams: inodeParams,
			Inode:                inodeEntry.PathKey.Inode,
			MountID:              inodeEntry.PathKey.MountID,
		}

		path, err := resolver.Resolve(inodeEntry.PathKey, false)
		if err == nil {
			record.FilePath = path
		}

		dumps = append(dumps, record)

		count++
		if count == int(info.MaxEntries) {
			break
		}
	}

	return dumps, nil
}

func dumpDiscarderStats(buffers ...*ebpf.Map) (map[string]discarder.Stats, error) {
	numCPU, err := utils.NumCPU()
	if err != nil {
		return nil, fmt.Errorf("couldn't fetch the host CPU count: %w", err)
	}

	stats := make(map[string]discarder.Stats)
	perCPU := make([]discarder.Stats, numCPU)

	var eventType uint32
	for _, buffer := range buffers {
		iterator := buffer.Iterate()

		for iterator.Next(&eventType, &perCPU) {
			for _, stat := range perCPU {
				key := model.EventType(eventType).String()

				entry, exists := stats[key]
				if !exists {
					stats[key] = discarder.Stats{
						DiscarderAdded: stat.DiscarderAdded,
						EventDiscarded: stat.EventDiscarded,
					}
				} else {
					entry.DiscarderAdded += stat.DiscarderAdded
					entry.EventDiscarded += stat.EventDiscarded
				}
			}
		}
	}

	return stats, nil
}

// DumpDiscarders removes all the discarders
func dumpDiscarders(resolver *dentry.Resolver, inodeMap, statsFB, statsBB *ebpf.Map) (DiscardersDump, error) {
	seclog.Debugf("Dumping discarders")

	dump := DiscardersDump{
		Date: time.Now(),
	}

	inodes, err := dumpInodeDiscarders(resolver, inodeMap)
	if err != nil {
		return dump, err
	}
	dump.Inodes = inodes

	stats, err := dumpDiscarderStats(statsFB, statsBB)
	if err != nil {
		return dump, err
	}
	dump.Stats = stats

	return dump, nil
}

func dnsResponseCodeDiscarderHandler(_ *rules.RuleSet, event *model.Event, probe *EBPFProbe, _ Discarder) (bool, error) {
	dnsResponse := &event.DNS

	if !dnsResponse.HasResponse() {
		return false, nil
	}

	mask := uint16(1)
	mask <<= dnsResponse.Response.ResponseCode
	dnsMask |= mask

	bufferSelector, err := managerhelper.Map(probe.Manager, "filtered_dns_rcodes")
	if err != nil {
		return false, err
	}

	err = bufferSelector.Put(uint32(0), dnsMask)
	if err != nil {
		return false, err
	}

	seclog.Tracef("DNS discarder for response code: %d", dnsResponse.Response.ResponseCode)
	return true, nil
}

func init() {
	allDiscarderHandlers["open.file.path"] = filenameDiscarderWrapper(model.FileOpenEventType,
		func(event *model.Event) (eval.Field, *model.FileEvent, bool) {
			return "open.file.path", &event.Open.File, false
		})

	allDiscarderHandlers["mkdir.file.path"] = filenameDiscarderWrapper(model.FileMkdirEventType,
		func(event *model.Event) (eval.Field, *model.FileEvent, bool) {
			return "mkdir.file.path", &event.Mkdir.File, false
		})

	allDiscarderHandlers["unlink.file.path"] = filenameDiscarderWrapper(model.FileUnlinkEventType,
		func(event *model.Event) (eval.Field, *model.FileEvent, bool) {
			return "unlink.file.path", &event.Unlink.File, true
		})

	allDiscarderHandlers["rmdir.file.path"] = filenameDiscarderWrapper(model.FileRmdirEventType,
		func(event *model.Event) (eval.Field, *model.FileEvent, bool) {
			return "rmdir.file.path", &event.Rmdir.File, false
		})

	allDiscarderHandlers["chmod.file.path"] = filenameDiscarderWrapper(model.FileChmodEventType,
		func(event *model.Event) (eval.Field, *model.FileEvent, bool) {
			return "chmod.file.path", &event.Chmod.File, false
		})

	allDiscarderHandlers["chown.file.path"] = filenameDiscarderWrapper(model.FileChownEventType,
		func(event *model.Event) (eval.Field, *model.FileEvent, bool) {
			return "chown.file.path", &event.Chown.File, false
		})

	allDiscarderHandlers["utimes.file.path"] = filenameDiscarderWrapper(model.FileUtimesEventType,
		func(event *model.Event) (eval.Field, *model.FileEvent, bool) {
			return "utimes.file.path", &event.Utimes.File, false
		})

	allDiscarderHandlers["setxattr.file.path"] = filenameDiscarderWrapper(model.FileSetXAttrEventType,
		func(event *model.Event) (eval.Field, *model.FileEvent, bool) {
			return "setxattr.file.path", &event.SetXAttr.File, false
		})

	allDiscarderHandlers["removexattr.file.path"] = filenameDiscarderWrapper(model.FileRemoveXAttrEventType,
		func(event *model.Event) (eval.Field, *model.FileEvent, bool) {
			return "removexattr.file.path", &event.RemoveXAttr.File, false
		})

	allDiscarderHandlers["mmap.file.path"] = filenameDiscarderWrapper(model.MMapEventType,
		func(event *model.Event) (eval.Field, *model.FileEvent, bool) {
			return "mmap.file.path", &event.MMap.File, false
		})

	allDiscarderHandlers["splice.file.path"] = filenameDiscarderWrapper(model.SpliceEventType,
		func(event *model.Event) (eval.Field, *model.FileEvent, bool) {
			return "splice.file.path", &event.Splice.File, false
		})

	allDiscarderHandlers["chdir.file.path"] = filenameDiscarderWrapper(model.FileOpenEventType,
		func(event *model.Event) (eval.Field, *model.FileEvent, bool) {
			return "chdir.file.path", &event.Open.File, false
		})

	allDiscarderHandlers["dns.response.code"] = dnsResponseCodeDiscarderHandler

	// Add all the discarders to the SupportedDiscarders map
	for field := range allDiscarderHandlers {
		SupportedDiscarders[field] = true
	}
}
