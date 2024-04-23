package kernel

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/opentracing/opentracing-go"

	"github.com/linuxkerneltravel/lmp/eBPF_Supermarket/sidecar/bpf/podnet"
	"github.com/linuxkerneltravel/lmp/eBPF_Supermarket/sidecar/visualization"
)

var TimeOffset = time.Now()

type SidecarOpt struct {
	SidecarPort int
	ServicePort int
	LocalIP     string
	PodIp       string
	NodeIp      string
}

// type NetworkStackEvent podnet.Event

type ConnectionType int32

const (
	EST     ConnectionType = 0
	TRA     ConnectionType = 1
	TER     ConnectionType = 2
	ACK     ConnectionType = 3
	UDP     ConnectionType = 4
	UNKNOWN ConnectionType = 5
)

type DirectionType int32

const (
	SIDECAR DirectionType = 0 // from service to sidecar
	SERVICE DirectionType = 1 // from sidecar to service
	CALLER  DirectionType = 2 // from pod to remote
	POD     DirectionType = 3 // from remote to pod
	REMOTE  DirectionType = 4 // from local host to remote host
	LOCAL   DirectionType = 5 // from remote host to local host
	OTHER   DirectionType = 6
)

type ConnectionEstablishmentInPod struct {
	toService podnet.EventList
	toSidecar podnet.EventList
	ack       podnet.EventList
}

type DataTransferInPod struct {
	req podnet.EventList
	res podnet.EventList
	ack podnet.EventList
}

type ConnectionTerminationInPod struct {
	toService podnet.EventList
	toSidecar podnet.EventList
	ack       podnet.EventList
}

type AcknowledgementsInPod struct {
	e podnet.EventList
}

type InPodConnectionOverall struct {
	Ce ConnectionEstablishmentInPod
	Dt DataTransferInPod
	Ct ConnectionTerminationInPod
	Ak AcknowledgementsInPod
}

type ConnectionEstablishmentOutPod struct {
	toCaller podnet.EventList
	toPod    podnet.EventList
	ack      podnet.EventList
}

type DataTransferOutPod struct {
	req    podnet.EventList
	reqAck podnet.EventList
	res    podnet.EventList
	resAck podnet.EventList
}

type ConnectionTerminationOutPod struct {
	toCaller podnet.EventList
	toPod    podnet.EventList
	ack      podnet.EventList
}

type AcknowledgementsOutPod struct {
	e podnet.EventList
}

type OutPodConnectionOverall struct {
	Ce ConnectionEstablishmentOutPod
	Dt DataTransferOutPod
	Ct ConnectionTerminationOutPod
	Ak AcknowledgementsOutPod
}

type ConnectIdType int

var globalCurrentConnId = 0

// getConnectId gets identification (sidecar's random port, usually) for network event in certain connection
func (s SidecarOpt) getConnectId(sPort int, dPort int) (ConnectIdType, error) {
	if sPort == s.ServicePort || sPort == s.SidecarPort {
		return ConnectIdType(dPort), nil
	} else if dPort == s.ServicePort || dPort == s.SidecarPort {
		return ConnectIdType(sPort), nil
	} else {
		return ConnectIdType(globalCurrentConnId), fmt.Errorf("bad match for port %d -> %d", sPort, dPort)
	}
}

// getPacketDirection gets the destination of this network event
// TODO: adapt to the network of the pod
func (s SidecarOpt) getPacketDirection(e podnet.Event) DirectionType {
	if e.SAddr == s.LocalIP && e.DAddr == s.LocalIP { // in-pod network event
		if e.Dport == s.ServicePort {
			return SERVICE
		} else if e.Sport == s.ServicePort {
			return SIDECAR
		} else {
			return OTHER
		}
	}

	if s.PodIp == "UNSET" {
		return OTHER
	}
	if e.SAddr == s.PodIp { // from pod to remote
		if e.Sport == s.SidecarPort || e.Sport == s.ServicePort {
			return CALLER
		} else {
			return OTHER
		}
	} else if e.DAddr == s.PodIp { // from remote to pod
		if e.Dport == s.SidecarPort || e.Dport == s.ServicePort {
			return POD
		} else {
			return OTHER
		}
	}

	if s.NodeIp == "UNSET" {
		return OTHER
	}
	if e.SAddr == s.NodeIp { // from local host to remote host
		return REMOTE
	} else if e.DAddr == s.NodeIp { // from remote host to local host
		return LOCAL
	}

	return OTHER
}

// getConnectType get TCP flag from combined tcp flags
func getConnectType(e podnet.Event) ConnectionType {
	if e.TcpFlags == "ACK" {
		return ACK
	} else if strings.Contains(e.TcpFlags, "SYN") {
		return EST
	} else if strings.Contains(e.TcpFlags, "PSH") {
		return TRA
	} else if strings.Contains(e.TcpFlags, "FIN") {
		return TER
	} else if e.L4Proto == "UDP" {
		return UDP
	} else {
		return UNKNOWN
	}
}

// monitorLoopInPod does monitor tasks in parallel
func monitorLoopInPod(heap *map[ConnectIdType]InPodConnectionOverall, timeout time.Duration, podName string, ch <-chan bool, outSpanPairId <-chan string) {
	for {
		select {
		case <-time.Tick(timeout): // DO NOT USE THIS IN MULTI-THREAD SITUATION
			for connectId, conn := range *heap {
				t, closer := visualization.InitJaeger(podName + "-in")
				defer closer.Close()

				// sort events by time
				sort.Sort(conn.Ce.toService)
				sort.Sort(conn.Ce.toSidecar)
				sort.Sort(conn.Dt.req)
				sort.Sort(conn.Dt.res)
				sort.Sort(conn.Ct.toService)
				sort.Sort(conn.Ct.toSidecar)
				sort.Sort(conn.Ak.e)

				// insert ack to ce and ct
				for i := 0; i < len(conn.Ak.e); i++ {
					if conn.Ak.e[i].Time < conn.Dt.req[0].Time {
						conn.Ce.ack = append(conn.Ce.ack, conn.Ak.e[i])
					} else if conn.Ak.e[i].Time < conn.Ct.toService[0].Time {
						conn.Dt.ack = append(conn.Dt.ack, conn.Ak.e[i])
					} else {
						conn.Ct.ack = append(conn.Ct.ack, conn.Ak.e[i])
					}
				}

				allSpan := t.StartSpan(
					"Inner Pod",
					opentracing.StartTime(TimeOffset.Add(conn.Ce.toService[0].Time)),
					opentracing.Tag{Key: "Connection ID", Value: strconv.Itoa(int(connectId))},
				)

				connectionEstablishmentSpan := t.StartSpan(
					"Connection Establishment",
					opentracing.ChildOf(allSpan.Context()),
					opentracing.StartTime(TimeOffset.Add(conn.Ce.toService[0].Time)),
				)

				toServiceSynSpan := t.StartSpan(
					"SYN to Service",
					opentracing.ChildOf(connectionEstablishmentSpan.Context()),
					opentracing.StartTime(TimeOffset.Add(conn.Ce.toService[0].Time)),
				)
				toServiceSynSpan.FinishWithOptions(
					opentracing.FinishOptions{
						FinishTime: TimeOffset.Add(conn.Ce.toService[len(conn.Ce.toService)-1].Time),
					},
				)

				toSidecarSynSpan := t.StartSpan(
					"SYN to Sidecar",
					opentracing.ChildOf(connectionEstablishmentSpan.Context()),
					opentracing.StartTime(TimeOffset.Add(conn.Ce.toSidecar[0].Time)),
				)
				toSidecarSynSpan.FinishWithOptions(
					opentracing.FinishOptions{
						FinishTime: TimeOffset.Add(conn.Ce.toSidecar[len(conn.Ce.toSidecar)-1].Time),
					},
				)

				connectionEstablishmentSpan.FinishWithOptions(
					opentracing.FinishOptions{
						FinishTime: TimeOffset.Add(conn.Ce.ack[len(conn.Ce.ack)-1].Time),
					},
				)

				if len(conn.Dt.req) > 0 {
					dataTransferSpan := t.StartSpan(
						"Data Transfer",
						opentracing.ChildOf(allSpan.Context()),
						opentracing.StartTime(TimeOffset.Add(conn.Dt.req[0].Time)),
					)

					reqSpan := t.StartSpan(
						"Request from Sidecar to Service",
						opentracing.ChildOf(dataTransferSpan.Context()),
						opentracing.StartTime(TimeOffset.Add(conn.Dt.req[0].Time)),
					)
					reqSpan.FinishWithOptions(
						opentracing.FinishOptions{
							FinishTime: TimeOffset.Add(conn.Dt.req[len(conn.Dt.req)-1].Time),
						},
					)

					resSpan := t.StartSpan(
						"Response from Sidecar to Service",
						opentracing.ChildOf(dataTransferSpan.Context()),
						opentracing.StartTime(TimeOffset.Add(conn.Dt.res[0].Time)),
					)
					resSpan.FinishWithOptions(
						opentracing.FinishOptions{
							FinishTime: TimeOffset.Add(conn.Dt.res[len(conn.Dt.res)-1].Time),
						},
					)

					dataTransferSpan.FinishWithOptions(
						opentracing.FinishOptions{
							FinishTime: TimeOffset.Add(conn.Dt.ack[len(conn.Dt.ack)-1].Time),
						},
					)
				}

				connectionTerminationSpan := t.StartSpan(
					"Connection Termination",
					opentracing.ChildOf(allSpan.Context()),
					opentracing.StartTime(TimeOffset.Add(conn.Ct.toService[0].Time)),
				)

				toServiceFinSpan := t.StartSpan(
					"FIN to Service",
					opentracing.ChildOf(connectionTerminationSpan.Context()),
					opentracing.StartTime(TimeOffset.Add(conn.Ct.toService[0].Time)),
				)
				toServiceFinSpan.FinishWithOptions(
					opentracing.FinishOptions{
						FinishTime: TimeOffset.Add(conn.Ct.toService[len(conn.Ct.toService)-1].Time),
					},
				)

				toSidecarFinSpan := t.StartSpan(
					"FIN to Sidecar",
					opentracing.ChildOf(connectionTerminationSpan.Context()),
					opentracing.StartTime(TimeOffset.Add(conn.Ct.toSidecar[0].Time)),
				)
				toSidecarFinSpan.FinishWithOptions(
					opentracing.FinishOptions{
						FinishTime: TimeOffset.Add(conn.Ct.toSidecar[len(conn.Ct.toSidecar)-1].Time),
					},
				)

				connectionTerminationSpan.FinishWithOptions(
					opentracing.FinishOptions{
						FinishTime: TimeOffset.Add(conn.Ct.ack[len(conn.Ct.ack)-1].Time),
					},
				)

				allSpan.FinishWithOptions(
					opentracing.FinishOptions{
						FinishTime: TimeOffset.Add(conn.Ak.e[len(conn.Ak.e)-1].Time),
					},
				)

				delete(*heap, connectId)
			}
		case <-ch:
			break
		}
	}
}

// monitorLoopOutPod does monitor tasks in parallel
func monitorLoopOutPod(heap *map[ConnectIdType]OutPodConnectionOverall, timeout time.Duration, podName string, ch <-chan bool, outSpanPairId chan<- string) {
	for {
		select {
		case <-time.Tick(timeout): // DO NOT USE THIS IN MULTI-THREAD SITUATION
			for connectId, conn := range *heap {
				t, closer := visualization.InitJaeger(podName + "-out")
				defer closer.Close()

				// sort events by time
				sort.Sort(conn.Ce.toCaller)
				sort.Sort(conn.Ce.toPod)
				sort.Sort(conn.Dt.req)
				sort.Sort(conn.Dt.res)
				sort.Sort(conn.Ct.toCaller)
				sort.Sort(conn.Ct.toPod)
				sort.Sort(conn.Ak.e)

				// insert ack to ce and ct
				for i := 0; i < len(conn.Ak.e); i++ {
					if conn.Ak.e[i].Time < conn.Dt.req[0].Time {
						conn.Ce.ack = append(conn.Ce.ack, conn.Ak.e[i])
					} else if conn.Ak.e[i].Time < conn.Dt.res[0].Time {
						conn.Dt.reqAck = append(conn.Dt.reqAck, conn.Ak.e[i])
					} else if conn.Ak.e[i].Time < conn.Ct.toPod[0].Time {
						conn.Dt.resAck = append(conn.Dt.resAck, conn.Ak.e[i])
					} else {
						conn.Ct.ack = append(conn.Ct.ack, conn.Ak.e[i])
					}
				}

				allSpan := t.StartSpan(
					"Out of Pod",
					opentracing.StartTime(TimeOffset.Add(conn.Ce.toPod[0].Time)),
					opentracing.Tag{Key: "Connection ID", Value: strconv.Itoa(int(connectId))},
				)

				connectionEstablishmentSpan := t.StartSpan(
					"Connection Establishment",
					opentracing.ChildOf(allSpan.Context()),
					opentracing.StartTime(TimeOffset.Add(conn.Ce.toPod[0].Time)),
				)

				toPodSynSpan := t.StartSpan(
					"SYN to Pod",
					opentracing.ChildOf(connectionEstablishmentSpan.Context()),
					opentracing.StartTime(TimeOffset.Add(conn.Ce.toPod[0].Time)),
				)
				toPodSynSpan.FinishWithOptions(
					opentracing.FinishOptions{
						FinishTime: TimeOffset.Add(conn.Ce.toPod[len(conn.Ce.toPod)-1].Time),
					},
				)

				toCallerSynSpan := t.StartSpan(
					"SYN to Caller",
					opentracing.ChildOf(connectionEstablishmentSpan.Context()),
					opentracing.StartTime(TimeOffset.Add(conn.Ce.toCaller[0].Time)),
				)
				toCallerSynSpan.FinishWithOptions(
					opentracing.FinishOptions{
						FinishTime: TimeOffset.Add(conn.Ce.toCaller[len(conn.Ce.toCaller)-1].Time),
					},
				)

				connectionEstablishmentSpan.FinishWithOptions(
					opentracing.FinishOptions{
						FinishTime: TimeOffset.Add(conn.Ce.ack[len(conn.Ce.ack)-1].Time),
					},
				)

				if len(conn.Dt.req) > 0 {
					dataTransferSpan := t.StartSpan(
						"Data Transfer",
						opentracing.ChildOf(allSpan.Context()),
						opentracing.StartTime(TimeOffset.Add(conn.Dt.req[0].Time)))

					reqSpan := t.StartSpan(
						"Request from Caller to Pod",
						opentracing.ChildOf(dataTransferSpan.Context()),
						opentracing.StartTime(TimeOffset.Add(conn.Dt.req[0].Time)),
					)
					reqSpan.FinishWithOptions(
						opentracing.FinishOptions{
							FinishTime: TimeOffset.Add(conn.Dt.req[len(conn.Dt.req)-1].Time),
						},
					)

					resSpan := t.StartSpan(
						"Response from Pod to Caller",
						opentracing.ChildOf(dataTransferSpan.Context()),
						opentracing.StartTime(TimeOffset.Add(conn.Dt.res[0].Time)),
					)
					resSpan.FinishWithOptions(
						opentracing.FinishOptions{
							FinishTime: TimeOffset.Add(conn.Dt.res[len(conn.Dt.res)-1].Time),
						},
					)

					dataTransferSpan.FinishWithOptions(
						opentracing.FinishOptions{
							FinishTime: TimeOffset.Add(conn.Dt.resAck[len(conn.Dt.resAck)-1].Time),
						},
					)
				}

				connectionTerminationSpan := t.StartSpan(
					"Connection Termination",
					opentracing.ChildOf(allSpan.Context()),
					opentracing.StartTime(TimeOffset.Add(conn.Ct.toPod[0].Time)),
				)

				toPodFinSpan := t.StartSpan(
					"FIN to Pod",
					opentracing.ChildOf(connectionTerminationSpan.Context()),
					opentracing.StartTime(TimeOffset.Add(conn.Ct.toPod[0].Time)),
				)
				toPodFinSpan.FinishWithOptions(
					opentracing.FinishOptions{
						FinishTime: TimeOffset.Add(conn.Ct.toPod[len(conn.Ct.toPod)-1].Time),
					},
				)

				toCallerFinSpan := t.StartSpan(
					"FIN to Caller",
					opentracing.ChildOf(connectionTerminationSpan.Context()),
					opentracing.StartTime(TimeOffset.Add(conn.Ct.toCaller[0].Time)),
				)
				toCallerFinSpan.FinishWithOptions(
					opentracing.FinishOptions{
						FinishTime: TimeOffset.Add(conn.Ct.toCaller[len(conn.Ct.toCaller)-1].Time),
					},
				)

				connectionTerminationSpan.FinishWithOptions(
					opentracing.FinishOptions{
						FinishTime: TimeOffset.Add(conn.Ct.ack[len(conn.Ct.ack)-1].Time),
					},
				)

				allSpan.FinishWithOptions(
					opentracing.FinishOptions{
						FinishTime: TimeOffset.Add(conn.Ak.e[len(conn.Ak.e)-1].Time),
					},
				)

				delete(*heap, connectId)
			}
		case <-ch:
			break
		}
	}
}

// GetKernelNetworkEvent is an entrance to monitor network events
func GetKernelNetworkEvent(pidList []int, sidecarOpt SidecarOpt, podName string) {
	fmt.Printf("[INFO] got pod IP: %s, host IP: %s\n", sidecarOpt.PodIp, sidecarOpt.NodeIp)
	podIp := sidecarOpt.PodIp
	ch := make(chan podnet.Event, 100000)
	heartBeatInPod := make(chan bool)
	heartBeatOutPod := make(chan bool)
	outSpanPairId := make(chan string) // TODO: outSpanPairId is used to pair the outer network span with inner pod span
	allInPodEventHeap := make(map[ConnectIdType]InPodConnectionOverall)
	allOutPodEventHeap := make(map[ConnectIdType]OutPodConnectionOverall)

	go podnet.Probe(pidList, false, "", ch)   // probes inner pod events
	go podnet.Probe(pidList, true, podIp, ch) // probes outer pod events
	go monitorLoopInPod(&allInPodEventHeap, time.Second, podName, heartBeatInPod, outSpanPairId)
	go monitorLoopOutPod(&allOutPodEventHeap, time.Second, podName, heartBeatOutPod, outSpanPairId)

	for {
		event := <-ch
		direction := sidecarOpt.getPacketDirection(event)
		connectionType := getConnectType(event)
		if direction == SIDECAR || direction == SERVICE { // in-pod events
			id, err := sidecarOpt.getConnectId(event.Sport, event.Dport)
			conn, ok := allInPodEventHeap[id]
			if ok == false {
				conn = InPodConnectionOverall{}
			}
			if err != nil {
				fmt.Println(err)
			} else {
				// fmt.Println("connect id:", id, "direction:", direction, "type:", connectionType)
				heartBeatInPod <- true
				switch connectionType {
				case ACK:
					conn.Ak.e = append(conn.Ak.e, event)
				case EST:
					if direction == SERVICE {
						conn.Ce.toService = append(conn.Ce.toService, event)
					} else if direction == SIDECAR {
						conn.Ce.toSidecar = append(conn.Ce.toSidecar, event)
					} else {
						break
					}
				case TER:
					if direction == SERVICE {
						conn.Ct.toService = append(conn.Ct.toService, event)
					} else if direction == SIDECAR {
						conn.Ct.toSidecar = append(conn.Ct.toSidecar, event)
					} else {
						break
					}
				case TRA:
					if direction == SERVICE {
						conn.Dt.req = append(conn.Dt.req, event)
					} else if direction == SIDECAR {
						conn.Dt.res = append(conn.Dt.res, event)
					} else {
						break
					}
				default:
					break
				}
			}
			allInPodEventHeap[id] = conn
		} else if direction == POD || direction == CALLER { // out-of-pod events
			id, err := sidecarOpt.getConnectId(event.Sport, event.Dport)
			conn, ok := allOutPodEventHeap[id]
			if ok == false {
				conn = OutPodConnectionOverall{}
			}
			if err != nil {
				fmt.Println(err)
			} else {
				// fmt.Println("connect id:", id, "direction:", direction, "type:", connectionType)
				heartBeatOutPod <- true
				switch connectionType {
				case ACK:
					conn.Ak.e = append(conn.Ak.e, event)
				case EST:
					if direction == POD {
						conn.Ce.toPod = append(conn.Ce.toPod, event)
					} else if direction == CALLER {
						conn.Ce.toCaller = append(conn.Ce.toCaller, event)
					} else {
						break
					}
				case TER:
					if direction == POD {
						conn.Ct.toPod = append(conn.Ct.toPod, event)
					} else if direction == CALLER {
						conn.Ct.toCaller = append(conn.Ct.toCaller, event)
					} else {
						break
					}
				case TRA:
					if direction == POD {
						conn.Dt.req = append(conn.Dt.req, event)
					} else if direction == CALLER {
						conn.Dt.res = append(conn.Dt.res, event)
					} else {
						break
					}
				default:
					break
				}
			}
			allOutPodEventHeap[id] = conn
		} else {
			// fmt.Println("overlay package", direction)
		}
		// event.Print()
	}
}
