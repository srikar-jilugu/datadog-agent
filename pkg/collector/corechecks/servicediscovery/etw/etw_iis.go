// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build windows

// Package etw implements service discovery through ETW.
package etw

import (
	"encoding/binary"
	"sync"
	"sync/atomic"
	"unsafe"

	"github.com/DataDog/datadog-agent/comp/etw"
	etwimpl "github.com/DataDog/datadog-agent/comp/etw/impl"
	"github.com/DataDog/datadog-agent/pkg/util/log"
	"github.com/DataDog/datadog-agent/pkg/util/winutil"
	"github.com/DataDog/datadog-agent/pkg/util/winutil/iisconfig"
)

// iisDiscovery tracks ETW activities related to IIS.
type iisDiscovery struct {
	activities      map[etw.DDGUID]*etwActivity
	activitiesRWMux sync.RWMutex
	iisSites        map[uint32]*IISSite
	iisSitesRWMux   sync.RWMutex
	iisConfig       atomic.Pointer[iisconfig.DynamicIISConfig]
}

// IISSite represents a discovered IIS site.
type IISSite struct {
	AppPool                string
	SiteID                 uint32
	SiteName               string
	Port                   uint16
	firstActivityTimestamp uint64
	lastActivityTimestamp  uint64
}

// etwActivity represents preliminary information that is potentially related to an IIS site.
// This activity is cached until we can confirm or deny that the chain of activities is related to IIS.
type etwActivity struct {
	port      uint16
	timestamp uint64
}

// initialize sets up data structures for tracking ETW activities related to IIS.
func (iis *iisDiscovery) initialize() error {
	iis.activities = make(map[etw.DDGUID]*etwActivity)
	iis.iisSites = make(map[uint32]*IISSite)

	config, err := iisconfig.NewDynamicIISConfig()
	if err != nil {
		log.Warnf("Failed to create iis config %v", err)
		config = nil
	} else {
		err = config.Start()
		if err != nil {
			log.Warnf("Failed to start iis config %v", err)
			config = nil
		}
	}
	if config != nil {
		iis.iisConfig.Store(config)
	}

	return nil
}

// getActivity returns a cached ETW activity based on an activity ID.
func (iis *iisDiscovery) getActivity(activityID *etw.DDGUID) (*etwActivity, bool) {
	iis.activitiesRWMux.RLock()
	defer iis.activitiesRWMux.RUnlock()
	activity, found := iis.activities[*activityID]
	return activity, found
}

// trackActivity caches an ETW activity to be referenced later by another async activity.
func (iis *iisDiscovery) trackActivity(activityID *etw.DDGUID, activity *etwActivity) {
	iis.activitiesRWMux.Lock()
	defer iis.activitiesRWMux.Unlock()
	iis.activities[*activityID] = activity
}

// untrackActivity removes an ETW activity from cache.
func (iis *iisDiscovery) untrackActivity(activityID *etw.DDGUID) {
	iis.activitiesRWMux.Lock()
	defer iis.activitiesRWMux.Unlock()
	delete(iis.activities, *activityID)
}

// getIISSite returns a discovered IIS site based on a site ID.
func (iis *iisDiscovery) getIISSite(siteID uint32) (*IISSite, bool) {
	iis.iisSitesRWMux.RLock()
	defer iis.iisSitesRWMux.RUnlock()
	site, found := iis.iisSites[siteID]
	return site, found
}

// addIISSite adds an IIS site as part of discovered sites.
func (iis *iisDiscovery) addIISSite(siteID uint32, newSite *IISSite) {
	iis.iisSitesRWMux.Lock()
	defer iis.iisSitesRWMux.Unlock()

	// Check if this site has already been added or if it has newer information.
	site, found := iis.iisSites[siteID]
	if !found || newSite.lastActivityTimestamp > site.lastActivityTimestamp {
		iis.iisSites[siteID] = newSite
	}
}

//func (iis *iisDiscovery) clearIISSite(siteID uint32) {
//	iis.iisSitesRWMux.Lock()
//	defer iis.iisSitesRWMux.Unlock()
//	delete(iis.iisSites, siteID)
//}

// handleHTTPRequestTraceTaskRecvReq handles ETW Event #1 (HTTPRequestTraceTaskRecvReq)
// This provides the related activity ID that is used to associate IIS AppPool and site information.
func (iis *iisDiscovery) handleHTTPRequestTraceTaskRecvReq(eventInfo *etw.DDEventRecord) {
	activity, connFound := iis.getActivity(&eventInfo.EventHeader.ActivityID)
	if !connFound {
		return
	}

	rai := GetRelatedActivityID(eventInfo)
	if rai == nil {
		log.Warnf("* Warning!!!: ActivityId:%v. HTTPRequestTraceTaskRecvReq event should have a reference to related activity id\n\n",
			FormatGUID(eventInfo.EventHeader.ActivityID))
		return
	}

	// We need the related activity ID to later associate the port number (which we got from event #21)
	// with IIS AppPool and site information (event #3).
	var relatedActivity = etwActivity{
		port:      activity.port,
		timestamp: activity.timestamp,
	}

	iis.trackActivity(rai, &relatedActivity)
	iis.untrackActivity(&eventInfo.EventHeader.ActivityID)
}

// handleHTTPRequestTraceTaskDeliver handles ETW Event #3 (HTTPRequestTraceTaskDeliver)
// This provide IIS AppPool and site information if found.
func (iis *iisDiscovery) handleHTTPRequestTraceTaskDeliver(eventInfo *etw.DDEventRecord) {
	// 	typedef struct _EVENT_PARAM_HttpService_HTTPRequestTraceTaskDeliver
	// 	{
	// 		0:  uint64_t requestObj;
	// 		8:  uint64_t requestId;
	// 		16: uint32_t siteId;
	// 		20: uint8_t  requestQueueName[xxx];  // Unicode zero terminating string
	// 	        uint8_t  url[xxx];               // Unicode zero terminating string
	// 	        uint32_t status;
	// 	} EVENT_PARAM_HttpService_HTTPRequestTraceTaskDeliver;
	userData := etwimpl.GetUserData(eventInfo)

	// Check for size
	if eventInfo.UserDataLength < 24 {
		//parsingErrorCount++
		log.Errorf("*** Error: ActivityId:%v. User data length for EVENT_PARAM_HttpService_HTTPRequestTraceTaskDeliver is too small %v\n\n",
			FormatGUID(eventInfo.EventHeader.ActivityID), uintptr(eventInfo.UserDataLength))
		return
	}

	activity, connFound := iis.getActivity(&eventInfo.EventHeader.ActivityID)
	if !connFound {
		return
	}

	//	rai := getRelatedActivityID(eventInfo)
	//	if rai == nil {
	//		log.Warnf("* Warning!!!: ActivityId:%v. HTTPRequestTraceTaskRecvReq event should have a reference to related activity id\n\n",
	//			formatGUID(eventInfo.EventHeader.ActivityID))
	//		return
	//	}

	timestamp := winutil.FileTimeToUnixNano(uint64(eventInfo.EventHeader.TimeStamp))
	siteID := userData.GetUint32(16)

	site, siteFound := iis.getIISSite(siteID)

	if !siteFound {
		// Parse RequestQueueName
		appPoolOffset := 20
		appPool, _, appPoolFound, _ := userData.ParseUnicodeString(appPoolOffset)
		if !appPoolFound {
			//parsingErrorCount++
			log.Errorf("*** Error: ActivityId:%v. HTTPRequestTraceTaskDeliver could not find terminating zero for RequestQueueName\n\n",
				FormatGUID(eventInfo.EventHeader.ActivityID))

			// If problem stop tracking this
			iis.untrackActivity(&eventInfo.EventHeader.ActivityID)
			return
		}

		site = &IISSite{
			Port:                   activity.port,
			AppPool:                appPool,
			SiteID:                 userData.GetUint32(16),
			firstActivityTimestamp: timestamp,
			lastActivityTimestamp:  timestamp,
		}

		cfg := iis.iisConfig.Load()
		if cfg != nil {
			site.SiteName = cfg.GetSiteNameFromID(site.SiteID)
		}

		// TODO: purge orphaned sites.
		iis.addIISSite(siteID, site)
	} else {
		site.lastActivityTimestamp = timestamp
	}

	// We got the IIS info and don't need to track this connection anymore.
	iis.untrackActivity(&eventInfo.EventHeader.ActivityID)
}

// handleHTTPConnectionTraceTaskConnConn handles ETW Event #21 (HTTPConnectionTraceTaskConnConn)
// This is the first ETW event from an HTTP request, provides port and URL information.
func (iis *iisDiscovery) handleHTTPConnectionTraceTaskConnConn(eventInfo *etw.DDEventRecord) {
	// -----------------------------------
	// IP4
	//
	//  typedef struct _EVENT_PARAM_HttpService_HTTPConnectionTraceTaskConnConnect_IP4
	//  {
	//  	0:  uint64_t connectionObj;
	//  	8:  uint32_t localAddrLength;
	//  	12: uint16_t localSinFamily;
	//  	14: uint16_t localPort;          // hton
	//  	16: uint32_t localIpAddress;
	//  	20: uint64_t localZeroPad;
	//  	28: uint32_t remoteAddrLength;
	//  	32: uint16_t remoteSinFamily;
	//  	34: uint16_t remotePort;         // hton
	//  	36: uint32_t remoteIpAddress;
	//  	40: uint64_t remoteZeroPad;
	//      48:
	//  } EVENT_PARAM_HttpService_HTTPConnectionTraceTaskConnConnect_IP4;

	// -----------------------------------
	// IP6
	//
	// 28 bytes address mapped to sockaddr_in6 (https://docs.microsoft.com/en-us/windows/win32/api/ws2ipdef/ns-ws2ipdef-sockaddr_in6_lh)
	//
	//
	//  typedef struct _EVENT_PARAM_HttpService_HTTPConnectionTraceTaskConnConnect_IP4
	//  {
	//  	0:  uint64_t connectionObj;
	//  	8:  uint32_t localAddrLength;
	//  	12: uint16_t localSinFamily;
	//  	14: uint16_t localPort;
	//  	16: uint32_t localPadding_sin6_flowinfo;
	//  	20: uint16_t localIpAddress[8];
	//      36: uint32_t localPadding_sin6_scope_id;
	//  	40: uint32_t remoteAddrLength;
	//  	44: uint16_t remoteSinFamily;
	//  	46: uint16_t remotePort;
	//  	48: uint32_t remotePadding_sin6_flowinfo;
	//  	52: uint16_t remoteIpAddress[8];
	//      68: uint32_t remotePadding_sin6_scope_id;
	//      72:
	//  } EVENT_PARAM_HttpService_HTTPConnectionTraceTaskConnConnect_IP4;

	userData := unsafe.Slice(eventInfo.UserData, int(eventInfo.UserDataLength))

	// Check for size
	if eventInfo.UserDataLength < 48 {
		log.Errorf("*** Error: User data length for EVENT_ID_HttpService_HTTPConnectionTraceTaskConnConn is too small %v\n\n", uintptr(eventInfo.UserDataLength))
		return
	}

	localAddrLength := binary.LittleEndian.Uint32(userData[8:12])
	if localAddrLength != 16 && localAddrLength != 28 {
		log.Errorf("*** Error: ActivityId:%v. HTTPConnectionTraceTaskConnConn invalid local address size %v (only 16 or 28 allowed)\n\n",
			FormatGUID(eventInfo.EventHeader.ActivityID), localAddrLength)
		return
	}

	var activity etwActivity
	// we're _always_ the server
	if localAddrLength == 16 {
		remoteAddrLength := binary.LittleEndian.Uint32(userData[28:32])
		if remoteAddrLength != 16 {
			log.Errorf("*** Error: ActivityId:%v. HTTPConnectionTraceTaskConnConn invalid remote address size %v (only 16 allowed)\n\n",
				FormatGUID(eventInfo.EventHeader.ActivityID), localAddrLength)
		}

		// Local and remote ipaddress and port
		//connOpen.conn.tup.Family = binary.LittleEndian.Uint16(userData[12:14])
		activity.port = binary.BigEndian.Uint16(userData[14:16])
		//copy(connOpen.conn.tup.LocalAddr[:], userData[16:20])
		//connOpen.conn.tup.RemotePort = binary.BigEndian.Uint16(userData[34:36])
		//copy(connOpen.conn.tup.RemoteAddr[:], userData[36:40])
	} else {
		if eventInfo.UserDataLength < 72 {
			log.Errorf("*** Error: User data length for EVENT_ID_HttpService_HTTPConnectionTraceTaskConnConn is too small for IP6 %v\n\n", uintptr(eventInfo.UserDataLength))
			return
		}

		remoteAddrLength := binary.LittleEndian.Uint32(userData[40:44])
		if remoteAddrLength != 28 {
			log.Errorf("*** Error: ActivityId:%v. HTTPConnectionTraceTaskConnConn invalid remote address size %v (only 16 allowed)\n\n",
				FormatGUID(eventInfo.EventHeader.ActivityID), localAddrLength)
		}

		//  	20: uint16_t localIpAddress[8];
		//  	46: uint16_t remotePort;
		//  	52: uint16_t remoteIpAddress[8];
		//connOpen.conn.tup.Family = binary.LittleEndian.Uint16(userData[12:14])
		activity.port = binary.BigEndian.Uint16(userData[14:16])
		//copy(connOpen.conn.tup.LocalAddr[:], userData[20:36])
		//connOpen.conn.tup.RemotePort = binary.BigEndian.Uint16(userData[46:48])
		//copy(connOpen.conn.tup.RemoteAddr[:], userData[52:68])
	}

	// Track when this connection was found.
	activity.timestamp = winutil.FileTimeToUnixNano(uint64(eventInfo.EventHeader.TimeStamp))

	// Save port information into map. We don't know if this is IIS related.
	iis.trackActivity(&eventInfo.EventHeader.ActivityID, &activity)
}
