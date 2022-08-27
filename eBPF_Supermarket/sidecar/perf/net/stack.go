package net

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/opentracing/opentracing-go"

	"github.com/eswzy/podstat/bpf/podnet"
	"github.com/eswzy/podstat/visualization"
)

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
	UNKNOWN ConnectionType = 4
)

type DirectionType int32

const (
	SIDECAR DirectionType = 0
	SERVICE DirectionType = 1
	REMOTE  DirectionType = 2
	POD     DirectionType = 3
	HOST    DirectionType = 4
	OTHER   DirectionType = 5
)

type ConnectionEstablishment struct {
	toService podnet.EventList
	toSidecar podnet.EventList
	ack       podnet.EventList
}

type DataTransfer struct {
	req podnet.EventList
	res podnet.EventList
	ack podnet.EventList
}

type ConnectionTermination struct {
	toService podnet.EventList
	toSidecar podnet.EventList
	ack       podnet.EventList
}

type Acknowledgements struct {
	e podnet.EventList
}

type ConnectionOverall struct {
	Ce ConnectionEstablishment
	Dt DataTransfer
	Ct ConnectionTermination
	Ak Acknowledgements
}

type ConnectIdType int

// getConnectId gets identification (sidecar's random port, usually) for network event in certain connection
func (s SidecarOpt) getConnectId(sPort int, dPort int) (ConnectIdType, error) {
	if sPort == s.ServicePort {
		return ConnectIdType(dPort), nil
	} else if dPort == s.ServicePort {
		return ConnectIdType(sPort), nil
	} else {
		return 0, fmt.Errorf("bad match for port %d -> %d", sPort, dPort)
	}
}

// getPacketDirection gets the destination of this network event
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
			return REMOTE
		} else {
			return OTHER
		}
	} else if e.DAddr == s.PodIp { // from remote to pod
		// TODO: this requires verification
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
		return HOST
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
	} else {
		return UNKNOWN
	}
}

// monitorLoop does monitor tasks in parallel
func monitorLoop(heap *map[ConnectIdType]ConnectionOverall, timeout time.Duration, ch <-chan bool, podName string) {
	for {
		select {
		case <-time.Tick(timeout): // DO NOT USE THIS IN MULTI-THREAD SITUATION
			for connectId, conn := range *heap {
				t, closer := visualization.InitJaeger(podName + "-" + strconv.Itoa(int(connectId)))
				defer closer.Close()

				// sort events by time
				sort.Sort(conn.Ce.toService)
				sort.Sort(conn.Ce.toSidecar)
				sort.Sort(conn.Dt.req)
				sort.Sort(conn.Dt.res)
				sort.Sort(conn.Ct.toService)
				sort.Sort(conn.Ct.toSidecar)
				sort.Sort(conn.Ak.e)

				// TODO: do analysis and visualization here
				timeOffset := time.Now().Add(-conn.Ce.toService[0].Time)

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
					opentracing.StartTime(timeOffset.Add(conn.Ce.toService[0].Time)),
				)

				connectionEstablishmentSpan := t.StartSpan(
					"Connection Establishment",
					opentracing.ChildOf(allSpan.Context()),
					opentracing.StartTime(timeOffset.Add(conn.Ce.toService[0].Time)),
				)

				toServiceSynSpan := t.StartSpan(
					"SYN to Service",
					opentracing.ChildOf(connectionEstablishmentSpan.Context()),
					opentracing.StartTime(timeOffset.Add(conn.Ce.toService[0].Time)),
				)
				toServiceSynSpan.FinishWithOptions(
					opentracing.FinishOptions{
						FinishTime: timeOffset.Add(conn.Ce.toService[len(conn.Ce.toService)-1].Time),
					},
				)

				toSidecarSynSpan := t.StartSpan(
					"SYN to Sidecar",
					opentracing.ChildOf(connectionEstablishmentSpan.Context()),
					opentracing.StartTime(timeOffset.Add(conn.Ce.toSidecar[0].Time)),
				)
				toSidecarSynSpan.FinishWithOptions(
					opentracing.FinishOptions{
						FinishTime: timeOffset.Add(conn.Ce.toSidecar[len(conn.Ce.toSidecar)-1].Time),
					},
				)

				connectionEstablishmentSpan.FinishWithOptions(
					opentracing.FinishOptions{
						FinishTime: timeOffset.Add(conn.Ce.ack[len(conn.Ce.ack)-1].Time),
					},
				)

				dataTransferSpan := t.StartSpan(
					"Data Transfer",
					opentracing.ChildOf(allSpan.Context()),
					opentracing.StartTime(timeOffset.Add(conn.Dt.req[0].Time)),
				)

				reqSpan := t.StartSpan(
					"Request from sidecar to Service",
					opentracing.ChildOf(dataTransferSpan.Context()),
					opentracing.StartTime(timeOffset.Add(conn.Dt.req[0].Time)),
				)
				reqSpan.FinishWithOptions(
					opentracing.FinishOptions{
						FinishTime: timeOffset.Add(conn.Dt.req[len(conn.Dt.req)-1].Time),
					},
				)

				resSpan := t.StartSpan(
					"Response from sidecar to Service",
					opentracing.ChildOf(dataTransferSpan.Context()),
					opentracing.StartTime(timeOffset.Add(conn.Dt.res[0].Time)),
				)
				resSpan.FinishWithOptions(
					opentracing.FinishOptions{
						FinishTime: timeOffset.Add(conn.Dt.res[len(conn.Dt.res)-1].Time),
					},
				)

				dataTransferSpan.FinishWithOptions(
					opentracing.FinishOptions{
						FinishTime: timeOffset.Add(conn.Dt.ack[len(conn.Dt.ack)-1].Time),
					},
				)

				connectionTerminationSpan := t.StartSpan(
					"Connection Termination",
					opentracing.ChildOf(allSpan.Context()),
					opentracing.StartTime(timeOffset.Add(conn.Ct.toService[0].Time)),
				)

				toServiceFinSpan := t.StartSpan(
					"FIN to Service",
					opentracing.ChildOf(connectionTerminationSpan.Context()),
					opentracing.StartTime(timeOffset.Add(conn.Ct.toService[0].Time)),
				)
				toServiceFinSpan.FinishWithOptions(
					opentracing.FinishOptions{
						FinishTime: timeOffset.Add(conn.Ct.toService[len(conn.Ct.toService)-1].Time),
					},
				)

				toSidecarFinSpan := t.StartSpan(
					"FIN to Sidecar",
					opentracing.ChildOf(connectionTerminationSpan.Context()),
					opentracing.StartTime(timeOffset.Add(conn.Ct.toSidecar[0].Time)),
				)
				toSidecarFinSpan.FinishWithOptions(
					opentracing.FinishOptions{
						FinishTime: timeOffset.Add(conn.Ct.toSidecar[len(conn.Ct.toSidecar)-1].Time),
					},
				)

				connectionTerminationSpan.FinishWithOptions(
					opentracing.FinishOptions{
						FinishTime: timeOffset.Add(conn.Ct.ack[len(conn.Ct.ack)-1].Time),
					},
				)

				allSpan.FinishWithOptions(
					opentracing.FinishOptions{
						FinishTime: timeOffset.Add(conn.Ak.e[len(conn.Ak.e)-1].Time),
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
func GetKernelNetworkEvent(pidList []int, portList []int, sidecarOpt SidecarOpt, podname string) {
	var protocolList []string
	ch := make(chan podnet.Event, 100000)
	heartBeat := make(chan bool)
	allEventHeap := make(map[ConnectIdType]ConnectionOverall)

	go podnet.Probe(pidList, portList, protocolList, ch)
	go monitorLoop(&allEventHeap, time.Second, heartBeat, podname)

	for {
		event := <-ch
		direction := sidecarOpt.getPacketDirection(event)
		connectionType := getConnectType(event)
		if direction == SIDECAR || direction == SERVICE {
			id, err := sidecarOpt.getConnectId(event.Sport, event.Dport)
			conn, ok := allEventHeap[id]
			if ok == false {
				conn = ConnectionOverall{}
			}
			if err != nil {
				fmt.Println(err)
			} else {
				// fmt.Println("connect id:", id, "direction:", sidecarOpt.getPacketDirection(event), "type:", connectionType)
				heartBeat <- true
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

			allEventHeap[id] = conn
		} else {
			// fmt.Println("out of pod", direction)
		}
		// event.Print()
	}
}
