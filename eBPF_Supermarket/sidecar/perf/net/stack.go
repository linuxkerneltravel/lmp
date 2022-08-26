package net

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/eswzy/podstat/bpf/podnet"
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
	toService []podnet.Event
	toSidecar []podnet.Event
}

type DataTransfer struct {
	req []podnet.Event
	res []podnet.Event
}

type ConnectionTermination struct {
	toService []podnet.Event
	toSidecar []podnet.Event
}

type Acknowledgements struct {
	e []podnet.Event
}

type ConnectionOverall struct {
	Cs ConnectionEstablishment
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
func monitorLoop(heap *map[ConnectIdType]ConnectionOverall, timeout time.Duration, ch <-chan bool) {
	for {
		select {
		case <-time.Tick(timeout): // DO NOT USE THIS IN MULTI-THREAD SITUATION
			for connectId, conn := range *heap {
				// TODO: do analysis and visualization here
				b, _ := json.Marshal(conn)
				fmt.Println(string(b))
				fmt.Println(conn)

				delete(*heap, connectId)
			}
		case <-ch:
			break
		}
	}
}

// GetKernelNetworkEvent is an entrance to monitor network events
func GetKernelNetworkEvent(pidList []int, portList []int, sidecarOpt SidecarOpt) {
	var protocolList []string
	ch := make(chan podnet.Event, 100000)
	heartBeat := make(chan bool)
	allEventHeap := make(map[ConnectIdType]ConnectionOverall)

	go podnet.Probe(pidList, portList, protocolList, ch)
	go monitorLoop(&allEventHeap, time.Second, heartBeat)

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
				fmt.Println("connect id:", id, "direction:", sidecarOpt.getPacketDirection(event), "type:", connectionType)
				heartBeat <- true
				switch connectionType {
				case ACK:
					conn.Ak.e = append(conn.Ak.e, event)
				case EST:
					if direction == SERVICE {
						conn.Cs.toService = append(conn.Cs.toService, event)
					} else if direction == SIDECAR {
						conn.Cs.toSidecar = append(conn.Cs.toSidecar, event)
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
			fmt.Println("out of pod", direction)
		}
		// event.Print()
	}
}
