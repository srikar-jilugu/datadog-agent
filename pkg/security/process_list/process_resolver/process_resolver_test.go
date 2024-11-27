// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build linux

// Package processresolver holds processresolver related files
package processresolver

import (
	"testing"
	"time"

	processlist "github.com/DataDog/datadog-agent/pkg/security/process_list"
	cgroupModel "github.com/DataDog/datadog-agent/pkg/security/resolvers/cgroup/model"
	"github.com/DataDog/datadog-agent/pkg/security/secl/model"
	"github.com/stretchr/testify/assert"
	"golang.org/x/exp/slices"
)

func newFakeForkEvent(ppid, pid int, pathname string) *model.Event {
	e := model.NewFakeEvent()
	e.Type = uint32(model.ForkEventType)
	e.ProcessContext = &model.ProcessContext{}
	e.ProcessContext.PPid = uint32(ppid)
	e.ProcessContext.Pid = uint32(pid)
	e.ProcessContext.ForkTime = time.Now()
	e.ProcessContext.FileEvent.PathnameStr = pathname
	return e
}

func newFakeExecEvent(event *model.Event, pathname string) *model.Event {
	e := model.NewFakeEvent()
	e.Type = uint32(model.ExecEventType)
	e.ProcessContext = &model.ProcessContext{}
	e.ProcessContext.PPid = uint32(event.ProcessContext.PPid)
	e.ProcessContext.Pid = uint32(event.ProcessContext.Pid)
	e.ProcessContext.ForkTime = time.Now()
	e.ProcessContext.FileEvent.PathnameStr = pathname
	return e
}

type testStats struct {
	TotalProcessNodes   int64
	TotalExecNodes      int64
	CurrentProcessNodes int64
	CurrentExecNodes    int64
}

func (ts *testStats) AddProcess(nbTreads int64) {
	ts.TotalProcessNodes++
	ts.TotalExecNodes += nbTreads
	ts.CurrentProcessNodes++
	ts.CurrentExecNodes += nbTreads
}

func (ts *testStats) AddExec() {
	ts.TotalExecNodes++
	ts.CurrentExecNodes++
}

func (ts *testStats) DeleteProcess(nbThreads int64) {
	ts.CurrentProcessNodes--
	ts.CurrentExecNodes -= nbThreads
}

func (ts *testStats) ValidateCounters(t *testing.T, pl *processlist.ProcessList) {
	assert.Equal(t, ts.TotalProcessNodes, pl.Stats.TotalProcessNodes)
	assert.Equal(t, ts.TotalExecNodes, pl.Stats.TotalExecNodes)
	assert.Equal(t, ts.CurrentProcessNodes, pl.Stats.CurrentProcessNodes)
	assert.Equal(t, ts.CurrentExecNodes, pl.Stats.CurrentExecNodes)
	assert.Equal(t, int(ts.CurrentProcessNodes), pl.GetProcessCacheSize())
	assert.Equal(t, int(ts.CurrentExecNodes), pl.GetExecCacheSize())
}

func checkParentality(pl *processlist.ProcessList, pc *ProcessResolver, parent, child *model.Event) bool {
	// first, get cached processes
	cachedProcessParent := pl.GetCacheProcess(pc.GetProcessCacheKey(&parent.ProcessContext.Process))
	cachedProcessChild := pl.GetCacheProcess(pc.GetProcessCacheKey(&child.ProcessContext.Process))
	if cachedProcessParent == nil || cachedProcessChild == nil {
		return false
	}
	// then, ensure child is part of parent children
	if !slices.ContainsFunc(cachedProcessParent.Children, func(c *processlist.ProcessNode) bool {
		return pc.ProcessMatches(cachedProcessChild, c)
	}) {
		return false
	}

	// validate process / exec links
	// 1/ for parent
	cachedExecParent := pl.GetCacheExec(pc.GetExecCacheKey(&parent.ProcessContext.Process))
	if cachedExecParent == nil {
		return false
	}
	if !slices.ContainsFunc(cachedProcessParent.PossibleExecs, func(e *processlist.ExecNode) bool {
		return pc.ExecMatches(e, cachedExecParent)
	}) {
		return false
	}
	if cachedExecParent.ProcessLink != cachedProcessParent {
		return false
	}

	// 1/ for child
	cachedExecChild := pl.GetCacheExec(pc.GetExecCacheKey(&child.ProcessContext.Process))
	if cachedExecChild == nil {
		return false
	}

	if !slices.ContainsFunc(cachedProcessChild.PossibleExecs, func(e *processlist.ExecNode) bool {
		return pc.ExecMatches(e, cachedExecChild)
	}) {
		return false
	}

	if cachedExecChild.ProcessLink != cachedProcessChild {
		return false
	}
	return true
}

func isProcessAndExecPresent(pl *processlist.ProcessList, pc *ProcessResolver, event *model.Event) bool {
	// first, get cached process
	cachedProcess := pl.GetCacheProcess(pc.GetProcessCacheKey(&event.ProcessContext.Process))
	if cachedProcess == nil {
		return false
	}

	// validate process / exec links
	cachedExec := pl.GetCacheExec(pc.GetExecCacheKey(&event.ProcessContext.Process))
	if cachedExec == nil {
		return false
	}
	if !slices.ContainsFunc(cachedProcess.PossibleExecs, func(e *processlist.ExecNode) bool {
		return pc.ExecMatches(e, cachedExec)
	}) {
		return false
	}
	if cachedExec.ProcessLink != cachedProcess {
		return false
	}
	return true
}

func isProcessOrExecPresent(pl *processlist.ProcessList, pc *ProcessResolver, event *model.Event) bool {
	// first, check process presence
	cachedProcess := pl.GetCacheProcess(pc.GetProcessCacheKey(&event.ProcessContext.Process))
	if cachedProcess != nil {
		return true
	}

	// then exec
	cachedExec := pl.GetCacheExec(pc.GetExecCacheKey(&event.ProcessContext.Process))
	if cachedExec != nil {
		return true
	}
	return false
}

func isExecOfProcess(pl *processlist.ProcessList, pc *ProcessResolver, process, exec *model.Event) bool {
	cachedProcess := pl.GetCacheProcess(pc.GetProcessCacheKey(&process.ProcessContext.Process))
	cachedExec := pl.GetCacheExec(pc.GetExecCacheKey(&exec.ProcessContext.Process))
	if cachedProcess == nil || cachedExec == nil {
		return false
	}
	return slices.Contains(cachedProcess.PossibleExecs, cachedExec)
}

func isParentMissing(pl *processlist.ProcessList, pc *ProcessResolver, event *model.Event) bool {
	cachedProcess := pl.GetCacheProcess(pc.GetProcessCacheKey(&event.ProcessContext.Process))
	cachedParent := pl.GetCacheProcess(pc.GetParentProcessCacheKey(event))

	return cachedParent.CurrentExec == cachedProcess.CurrentExec
}

func TestFork1st(t *testing.T) {
	pc := NewProcessResolver()
	processList := processlist.NewProcessList(cgroupModel.WorkloadSelector{Image: "*", Tag: "*"}, nil, /* config  */
		[]model.EventType{model.ExecEventType, model.ForkEventType, model.ExitEventType}, pc /* ,nil  */, nil, nil, nil, nil, nil)
	stats := testStats{}

	// parent
	parent := newFakeForkEvent(0, 1, "/bin/parent")
	inserted, err := processList.Insert(parent, true, "")
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, true, inserted)
	stats.AddProcess(1)
	stats.ValidateCounters(t, processList)
	if !isProcessAndExecPresent(processList, pc, parent) {
		t.Fatal("didn't found cached parent")
	}

	// parent
	//     \ child
	child := newFakeForkEvent(1, 2, "/bin/child")
	inserted, err = processList.Insert(child, true, "")
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, true, inserted)
	stats.AddProcess(1)
	stats.ValidateCounters(t, processList)
	if checkParentality(processList, pc, parent, child) == false {
		t.Fatal("parent / child paternality not found")
	}

	if isParentMissing(processList, pc, child) {
		t.Fatal("lost parent")
	}

	// parent
	child.Type = uint32(model.ExitEventType)
	deleted, err := processList.Insert(child, true, "")
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, true, deleted)
	stats.DeleteProcess(1)
	stats.ValidateCounters(t, processList)
	if !isProcessAndExecPresent(processList, pc, parent) {
		t.Fatal("didn't found cached parent")
	}
	if isProcessOrExecPresent(processList, pc, child) {
		t.Fatal("child still present")
	}

	// nothing
	deleted, err = processList.DeleteCachedProcess(pc.GetProcessCacheKey(&parent.ProcessContext.Process), "")
	assert.Equal(t, true, deleted)
	stats.DeleteProcess(1)
	stats.ValidateCounters(t, processList)
	if isProcessOrExecPresent(processList, pc, parent) {
		t.Fatal("parent still present")
	}
}

//
// TODO: tests from pkg/security/resolvers/process/resolver_test.go to add:
//

func TestFork2nd(t *testing.T) {
	pc := NewProcessResolver()

	processList := processlist.NewProcessList(cgroupModel.WorkloadSelector{Image: "*", Tag: "*"}, nil, /* config  */
		[]model.EventType{model.ExecEventType, model.ForkEventType, model.ExitEventType}, pc /* ,nil  */, nil, nil, nil, nil, nil)
	stats := testStats{}

	// parent
	parent := newFakeForkEvent(0, 1, "/bin/parent")
	new, err := processList.Insert(parent, true, "")
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, true, new)
	stats.AddProcess(1)
	stats.ValidateCounters(t, processList)

	if !isProcessAndExecPresent(processList, pc, parent) {
		t.Fatal("didn't found cached parent")
	}

	// // parent
	// //     \ child
	child := newFakeForkEvent(1, 2, "/bin/child")
	new, err = processList.Insert(child, true, "")
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, true, new)
	stats.AddProcess(1)
	stats.ValidateCounters(t, processList)
	if checkParentality(processList, pc, parent, child) == false {
		t.Fatal("parent / child paternality not found")
	}

	// // [parent]
	// //     \ [child]
	parent.Type = uint32(model.ExitEventType)
	deleted, err := processList.Insert(parent, true, "")
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, true, deleted)

	// Parent process should be removed
	stats.DeleteProcess(1)
	stats.ValidateCounters(t, processList)
	// Child process should be attached to another process
	if checkParentality(processList, pc, parent, child) == true {
		t.Fatal("this process should no longer the parent")
	}

	if isProcessOrExecPresent(processList, pc, parent) {
		t.Fatal("parent still present")
	}
	if !isProcessOrExecPresent(processList, pc, child) {
		t.Fatal("child should still be present")
	}

	child.Type = uint32(model.ExitEventType)
	deleted, err = processList.Insert(child, true, "")
	assert.Equal(t, true, deleted)
	stats.DeleteProcess(1)
	stats.ValidateCounters(t, processList)
	if isProcessOrExecPresent(processList, pc, child) {
		t.Fatal("child shoul not be present")
	}
}
func TestForkExec(t *testing.T) {

	pc := NewProcessResolver()

	processList := processlist.NewProcessList(cgroupModel.WorkloadSelector{Image: "*", Tag: "*"}, nil, /* config  */
		[]model.EventType{model.ExecEventType, model.ForkEventType, model.ExitEventType}, pc /* ,nil  */, nil, nil, nil, nil, nil)
	stats := testStats{}

	// parent
	parent := newFakeForkEvent(0, 1, "/bin/parent")
	new, err := processList.Insert(parent, true, "")
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, true, new)
	stats.AddProcess(1)
	stats.ValidateCounters(t, processList)
	if !isProcessAndExecPresent(processList, pc, parent) {
		t.Fatal("didn't found cached parent")
	}

	// parent
	//     \ child
	child := newFakeForkEvent(1, 2, "/bin/child")
	new, err = processList.Insert(child, true, "")
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, true, new)
	stats.AddProcess(1)
	stats.ValidateCounters(t, processList)
	if !checkParentality(processList, pc, parent, child) {
		t.Fatal("parent / child paternality not found")
	}

	// parent
	//     \ child -> exec
	exec := newFakeExecEvent(child, "bin/exec")
	new, err = processList.Insert(exec, true, "")
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, true, new)
	if !checkParentality(processList, pc, parent, exec) {
		t.Fatal("parent / exec paternality not found")
	}
	if !isExecOfProcess(processList, pc, child, exec) {
		t.Fatal("process / exec relation not present")
	}
	stats.AddExec()
	stats.ValidateCounters(t, processList)

	// nothing
	parent.Type = uint32(model.ExitEventType)
	deleted, err := processList.Insert(parent, true, "")
	assert.Equal(t, true, deleted)
	stats.DeleteProcess(1)
	stats.ValidateCounters(t, processList)
	if isProcessOrExecPresent(processList, pc, parent) {
		t.Fatal("parent still present")
	}

	child.Type = uint32(model.ExitEventType)
	deleted, err = processList.Insert(child, true, "")
	assert.Equal(t, true, deleted)
	stats.DeleteProcess(2)
	stats.ValidateCounters(t, processList)

	if isProcessOrExecPresent(processList, pc, parent) {
		t.Fatal("child still present")
	}

}
func TestForkExecExec(t *testing.T) {
	pc := NewProcessResolver()

	processList := processlist.NewProcessList(cgroupModel.WorkloadSelector{Image: "*", Tag: "*"}, nil, /* config  */
		[]model.EventType{model.ExecEventType, model.ForkEventType, model.ExitEventType}, pc /* ,nil  */, nil, nil, nil, nil, nil)
	stats := testStats{}

	// parent
	parent := newFakeForkEvent(0, 1, "/bin/parent")
	new, err := processList.Insert(parent, true, "")
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, true, new)
	stats.AddProcess(1)
	stats.ValidateCounters(t, processList)
	if !isProcessAndExecPresent(processList, pc, parent) {
		t.Fatal("didn't found cached parent")
	}

	// parent
	//     \ child
	child := newFakeForkEvent(1, 2, "/bin/child")
	new, err = processList.Insert(child, true, "")
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, true, new)
	stats.AddProcess(1)
	stats.ValidateCounters(t, processList)
	if checkParentality(processList, pc, parent, child) == false {
		t.Fatal("parent / child paternality not found")
	}

	// parent
	//     \ child -> exec1
	exec1 := newFakeExecEvent(child, "bin/exec1")
	new, err = processList.Insert(exec1, true, "")
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, true, new)
	if checkParentality(processList, pc, parent, exec1) == false {
		t.Fatal("parent / exec paternality not found")
	}
	if !isExecOfProcess(processList, pc, child, exec1) {
		t.Fatal("process / exec relation not present")
	}
	stats.AddExec()
	stats.ValidateCounters(t, processList)

	// [parent]
	//     \ child -> exec1 -> exec2
	exec2 := newFakeExecEvent(child, "bin/exec2")

	new, err = processList.Insert(exec2, true, "")
	if err != nil {
		t.Fatal(err)
	}
	if checkParentality(processList, pc, parent, exec2) == false {
		t.Fatal("parent / exec paternality not found")
	}
	if !isExecOfProcess(processList, pc, child, exec2) {
		t.Fatal("process / exec relation not present")
	}
	assert.Equal(t, true, new)
	stats.AddExec()
	stats.ValidateCounters(t, processList)

	// nothing
	parent.Type = uint32(model.ExitEventType)
	deleted, err := processList.Insert(parent, true, "")
	assert.Equal(t, true, deleted)
	stats.DeleteProcess(1)
	stats.ValidateCounters(t, processList)
	if isProcessOrExecPresent(processList, pc, parent) {
		t.Fatal("parent still present")
	}

	child.Type = uint32(model.ExitEventType)
	deleted, err = processList.Insert(child, true, "")
	assert.Equal(t, true, deleted)
	stats.DeleteProcess(3)
	stats.ValidateCounters(t, processList)

	if isProcessOrExecPresent(processList, pc, parent) {
		t.Fatal("child still present")
	}
}
func TestOrphanExec(t *testing.T) {

	pc := NewProcessResolver()

	processList := processlist.NewProcessList(cgroupModel.WorkloadSelector{Image: "*", Tag: "*"}, nil, /* config  */
		[]model.EventType{model.ExecEventType, model.ForkEventType, model.ExitEventType}, pc /* ,nil  */, nil, nil, nil, nil, nil)
	stats := testStats{}

	// parent
	parent := newFakeForkEvent(0, 1, "/bin/parent")
	new, err := processList.Insert(parent, true, "")
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, true, new)
	stats.AddProcess(1)
	stats.ValidateCounters(t, processList)
	if !isProcessAndExecPresent(processList, pc, parent) {
		t.Fatal("didn't found cached parent")
	}

	// parent
	//     \ child
	child := newFakeForkEvent(1, 2, "/bin/child")
	new, err = processList.Insert(child, true, "")
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, true, new)
	stats.AddProcess(1)
	stats.ValidateCounters(t, processList)
	if checkParentality(processList, pc, parent, child) == false {
		t.Fatal("parent / child paternality not found")
	}

	// [parent]
	//     \ child

	parent.Type = uint32(model.ExitEventType)
	deleted, err := processList.Insert(parent, true, "")

	assert.Equal(t, true, deleted)
	stats.DeleteProcess(1) // For parent
	stats.ValidateCounters(t, processList)
	if isProcessOrExecPresent(processList, pc, parent) {
		t.Fatal("parent still present")
	}
	if !isProcessAndExecPresent(processList, pc, child) {
		t.Fatal("child should be  present")
	}
	if checkParentality(processList, pc, parent, child) {
		t.Fatal("parent / child paternality still present")
	}

	// [parent]
	//     \ child -> exec
	exec := newFakeExecEvent(child, "bin/exec")

	new, err = processList.Insert(exec, true, "")
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, true, new)
	stats.AddExec()
	stats.ValidateCounters(t, processList)
	if !isExecOfProcess(processList, pc, child, exec) {
		t.Fatal("process / exec relation not present")
	}

	child.Type = uint32(model.ExitEventType)
	deleted, err = processList.Insert(child, true, "")
	assert.Equal(t, true, deleted)
	stats.DeleteProcess(2) // For parent
	stats.ValidateCounters(t, processList)
	if isProcessOrExecPresent(processList, pc, child) {
		t.Fatal("parent still present")
	}
	if isProcessOrExecPresent(processList, pc, exec) {
		t.Fatal("child should be  present")
	}

	if isExecOfProcess(processList, pc, child, exec) {
		t.Fatal("process / exec relation not present")
	}

}
func TestForkReuse(t *testing.T) {
	pc := NewProcessResolver()

	processList := processlist.NewProcessList(cgroupModel.WorkloadSelector{Image: "*", Tag: "*"}, nil, /* config  */
		[]model.EventType{model.ExecEventType, model.ForkEventType, model.ExitEventType}, pc /* ,nil  */, nil, nil, nil, nil, nil)
	stats := testStats{}

	// parent1
	parent1 := newFakeForkEvent(0, 1, "/bin/parent1")
	new, err := processList.Insert(parent1, true, "")
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, true, new)
	stats.AddProcess(1)
	stats.ValidateCounters(t, processList)
	if !isProcessAndExecPresent(processList, pc, parent1) {
		t.Fatal("didn't found cached parent")
	}

	// parent1
	//     \ child1
	child1 := newFakeForkEvent(1, 2, "/bin/child1")
	new, err = processList.Insert(child1, true, "")
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, true, new)
	stats.AddProcess(1)
	stats.ValidateCounters(t, processList)
	if checkParentality(processList, pc, parent1, child1) == false {
		t.Fatal("parent / child paternality not found")
	}

	// [parent1]
	//     \ child1 -> exec1
	parent1.Type = uint32(model.ExitEventType)
	deleted, err := processList.Insert(parent1, true, "")

	assert.Equal(t, true, deleted)
	stats.DeleteProcess(1) // For parent
	stats.ValidateCounters(t, processList)
	if isProcessOrExecPresent(processList, pc, parent1) {
		t.Fatal("parent still present")
	}
	if !isProcessAndExecPresent(processList, pc, child1) {
		t.Fatal("child should be  present")
	}
	if checkParentality(processList, pc, parent1, child1) {
		t.Fatal("parent / child paternality still present")
	}

	// [parent1]
	//     \ child1 -> exec1
	exec1 := newFakeExecEvent(child1, "bin/exec1")

	new, err = processList.Insert(exec1, true, "")
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, true, new)
	if !isExecOfProcess(processList, pc, child1, exec1) {
		t.Fatal("process / exec relation not present")
	}
	stats.AddExec()
	stats.ValidateCounters(t, processList)

	// [parent1:pid1]
	//     \ child1 -> exec1
	//
	// parent2:pid1
	parent2 := newFakeForkEvent(0, 1, "/bin/parent2")
	new, err = processList.Insert(parent2, true, "")
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, true, new)
	stats.AddProcess(1)
	stats.ValidateCounters(t, processList)
	if !isProcessAndExecPresent(processList, pc, parent2) {
		t.Fatal("didn't found cached parent")
	}

	// [parent1:pid1]
	//     \ child1 -> exec1
	//
	// parent2:pid1
	//     \ child2
	child2 := newFakeForkEvent(1, 3, "/bin/child1")
	new, err = processList.Insert(child2, true, "")
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, true, new)
	stats.AddProcess(1)
	stats.ValidateCounters(t, processList)
	if checkParentality(processList, pc, parent2, child2) == false {
		t.Fatal("parent / child paternality not found")
	}

	// parent2:pid1
	//     \ child2
	child1.Type = uint32(model.ExitEventType)
	deleted, err = processList.Insert(child1, true, "")

	assert.Equal(t, true, deleted)
	stats.DeleteProcess(2) // For parent
	stats.ValidateCounters(t, processList)
	if isProcessOrExecPresent(processList, pc, child1) {
		t.Fatal("child1 should not be  present")
	}
	if isExecOfProcess(processList, pc, child1, exec1) {
		t.Fatal("process / exec relation still present")
	}

	// [parent2:pid1]
	//     \ child2
	parent2.Type = uint32(model.ExitEventType)
	deleted, err = processList.Insert(parent2, true, "")

	assert.Equal(t, true, deleted)
	stats.DeleteProcess(1) // For parent
	stats.ValidateCounters(t, processList)
	if isProcessOrExecPresent(processList, pc, parent2) {
		t.Fatal("parent still present")
	}
	if !isProcessAndExecPresent(processList, pc, child2) {
		t.Fatal("child should be  present")
	}
	if checkParentality(processList, pc, parent2, child2) {
		t.Fatal("parent / child paternality still present")
	}

	// nothing
	child2.Type = uint32(model.ExitEventType)
	deleted, err = processList.Insert(child2, true, "")

	assert.Equal(t, true, deleted)
	stats.DeleteProcess(1)
	stats.ValidateCounters(t, processList)
	if isProcessOrExecPresent(processList, pc, child2) {
		t.Fatal("child1 should not be  present")
	}

}

func TestForkForkExec(t *testing.T) {

	pc := NewProcessResolver()

	processList := processlist.NewProcessList(cgroupModel.WorkloadSelector{Image: "*", Tag: "*"}, nil, /* config  */
		[]model.EventType{model.ExecEventType, model.ForkEventType, model.ExitEventType}, pc /* ,nil  */, nil, nil, nil, nil, nil)
	stats := testStats{}

	// parent
	parent := newFakeForkEvent(0, 1, "/bin/parent")
	new, err := processList.Insert(parent, true, "")
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, true, new)
	stats.AddProcess(1)
	stats.ValidateCounters(t, processList)
	if !isProcessAndExecPresent(processList, pc, parent) {
		t.Fatal("didn't found cached parent")
	}

	// parent
	//     \ child
	child := newFakeForkEvent(1, 2, "/bin/child")
	new, err = processList.Insert(child, true, "")
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, true, new)
	stats.AddProcess(1)
	stats.ValidateCounters(t, processList)
	if checkParentality(processList, pc, parent, child) == false {
		t.Fatal("parent / child paternality not found")
	}

	// parent
	//     \ child
	//          \ grandChild
	grandChild := newFakeForkEvent(2, 3, "/bin/grandChild")
	new, err = processList.Insert(grandChild, true, "")
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, true, new)
	stats.AddProcess(1)
	stats.ValidateCounters(t, processList)
	if checkParentality(processList, pc, child, grandChild) == false {
		t.Fatal("child / grandChild paternality not found")
	}

	// parent
	//     \ child -> childExec
	//          \ grandChild
	childExec := newFakeExecEvent(child, "bin/childExec")

	new, err = processList.Insert(childExec, true, "")
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, true, new)
	if checkParentality(processList, pc, parent, childExec) == false {
		t.Fatal("parent / childExec paternality not found")
	}
	if !isExecOfProcess(processList, pc, child, childExec) {
		t.Fatal("process / exec relation not found")
	}
	stats.AddExec()
	stats.ValidateCounters(t, processList)

	// [parent]
	//     \ child -> childExec
	//          \ grandChild
	parent.Type = uint32(model.ExitEventType)
	deleted, err := processList.Insert(parent, true, "")
	assert.Equal(t, true, deleted)
	stats.DeleteProcess(1) // For parent
	stats.ValidateCounters(t, processList)
	if isProcessOrExecPresent(processList, pc, parent) {
		t.Fatal("parent still present")
	}
	if !isProcessAndExecPresent(processList, pc, child) {
		t.Fatal("child still present")
	}
	if !isProcessOrExecPresent(processList, pc, grandChild) {
		t.Fatal("grandChild still present")
	}

	// [parent]
	//     \ [child] -> childExec
	//          \ grandChild
	child.Type = uint32(model.ExitEventType)
	deleted, err = processList.Insert(child, true, "")
	assert.Equal(t, true, deleted)
	stats.DeleteProcess(2) // For parent
	stats.ValidateCounters(t, processList)
	if isProcessOrExecPresent(processList, pc, child) {
		t.Fatal("child still present")
	}
	if !isProcessOrExecPresent(processList, pc, grandChild) {
		t.Fatal("grandChild still present")
	}

	// nothing
	grandChild.Type = uint32(model.ExitEventType)
	deleted, err = processList.Insert(grandChild, true, "")
	assert.Equal(t, true, deleted)
	stats.DeleteProcess(1) // For parent
	stats.ValidateCounters(t, processList)
	if isProcessOrExecPresent(processList, pc, grandChild) {
		t.Fatal("grandChild still present")
	}

}
func TestExecBomb(t *testing.T) {
	pc := NewProcessResolver()

	processList := processlist.NewProcessList(cgroupModel.WorkloadSelector{Image: "*", Tag: "*"}, nil, /* config  */
		[]model.EventType{model.ExecEventType, model.ForkEventType, model.ExitEventType}, pc /* ,nil  */, nil, nil, nil, nil, nil)
	stats := testStats{}

	// parent
	parent := newFakeForkEvent(0, 1, "/bin/parent")
	new, err := processList.Insert(parent, true, "")
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, true, new)
	stats.AddProcess(1)
	stats.ValidateCounters(t, processList)
	if !isProcessAndExecPresent(processList, pc, parent) {
		t.Fatal("didn't found cached parent")
	}

	// parent
	//     \ child
	child := newFakeForkEvent(1, 2, "/bin/child")
	new, err = processList.Insert(child, true, "")
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, true, new)
	stats.AddProcess(1)
	stats.ValidateCounters(t, processList)
	if checkParentality(processList, pc, parent, child) == false {
		t.Fatal("parent / child paternality not found")
	}

	// parent
	//     \ child -> exec1
	exec1 := newFakeExecEvent(child, "bin/exec1")

	new, err = processList.Insert(exec1, true, "")
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, true, new)
	if checkParentality(processList, pc, parent, exec1) == false {
		t.Fatal("parent / exec paternality not found")
	}
	if !isExecOfProcess(processList, pc, child, exec1) {
		t.Fatal("process / exec relation not present")
	}
	stats.AddExec()
	stats.ValidateCounters(t, processList)

	// parent
	//     \ child -> exec1 -> exec2
	exec2 := newFakeExecEvent(child, "bin/exec1")

	new, err = processList.Insert(exec2, true, "")
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, false, new) // should already be present
	if checkParentality(processList, pc, parent, exec2) == false {
		t.Fatal("parent / exec paternality not found")
	}
	if !isExecOfProcess(processList, pc, child, exec2) {
		t.Fatal("process / exec relation not present")
	}
	// Should not need to increment the number of execs
	stats.ValidateCounters(t, processList)

}

// No order between execs
func TestExecLostFork(t *testing.T) {

}

// No order between execs
func TestExecLostExec(t *testing.T) {

}

// No concept of exec exec
func TestIsExecExecRuntime(t *testing.T) {
}

// No concept of exec exec
func TestIsExecExecSnapshot(t *testing.T) {
}
