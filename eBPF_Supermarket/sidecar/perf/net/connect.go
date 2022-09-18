package net

import (
	"fmt"
	"strconv"

	"github.com/prometheus/client_golang/prometheus"
	"golang.org/x/exp/slices"

	"github.com/linuxkerneltravel/lmp/eBPF_Supermarket/sidecar/bpf/tcpaccept"
	"github.com/linuxkerneltravel/lmp/eBPF_Supermarket/sidecar/bpf/tcpconnect"
	"github.com/linuxkerneltravel/lmp/eBPF_Supermarket/sidecar/visualization"
)

type SidecarAcceptEvent tcpaccept.Event
type SidecarConnectEvent tcpconnect.Event
type ServiceAcceptEvent tcpaccept.Event

type RequestOverSidecar struct {
	SidecarAccept  SidecarAcceptEvent
	SidecarConnect SidecarConnectEvent
	ServiceAccept  ServiceAcceptEvent
}

// Empty placeholder event
var siae SidecarAcceptEvent
var sice SidecarConnectEvent
var seae ServiceAcceptEvent

// TODO: change to source ip and port, or other better choice?

type SidecarAcceptAndSidecarConnectKey struct {
	Pid int
	Tid int
}

type SidecarAcceptAndSidecarConnectValue struct {
	SidecarAccept  SidecarAcceptEvent
	SidecarConnect SidecarConnectEvent
	Ok             bool
}

type SidecarConnectAndServiceAcceptKey struct {
	SidecarIp   string // SAddr of SidecarConnectEvent, DAddr of ServiceAcceptEvent, S and D are always the same anyway
	SidecarPort int    // LPort of SidecarConnectEvent, DPort of ServiceAcceptEvent
}

type SidecarConnectAndServiceAcceptValue struct {
	SidecarConnect SidecarConnectEvent
	ServiceAccept  ServiceAcceptEvent
	Ok             bool
}

type RequestOverSidecarKey struct {
	SidecarConnect SidecarConnectEvent
}

type RequestOverSidecarValue struct {
	SidecarAccept  SidecarAcceptEvent
	SidecarConnect SidecarConnectEvent
	ServiceAccept  ServiceAcceptEvent
	Ok             bool
}

func fillRequestOverSidecarField(m *map[RequestOverSidecarKey]RequestOverSidecarValue, v1 *SidecarAcceptAndSidecarConnectValue, v2 *SidecarConnectAndServiceAcceptValue) {
	if v1 != nil {
		value, ok := (*m)[RequestOverSidecarKey{SidecarConnect: v1.SidecarConnect}]
		if ok == false || value.Ok || (value.Ok == false && value.ServiceAccept == seae) {
			(*m)[RequestOverSidecarKey{SidecarConnect: v1.SidecarConnect}] = RequestOverSidecarValue{SidecarAccept: v1.SidecarAccept, SidecarConnect: v1.SidecarConnect, Ok: false}
		} else {
			value.SidecarAccept = v1.SidecarAccept
			value.Ok = true
			(*m)[RequestOverSidecarKey{SidecarConnect: v1.SidecarConnect}] = value
			fmt.Println("assembled", value)
		}
	} else if v2 != nil {
		value, ok := (*m)[RequestOverSidecarKey{SidecarConnect: v2.SidecarConnect}]
		if ok == false || value.Ok || (value.Ok == false && value.SidecarAccept == siae) {
			(*m)[RequestOverSidecarKey{SidecarConnect: v2.SidecarConnect}] = RequestOverSidecarValue{SidecarConnect: v2.SidecarConnect, ServiceAccept: v2.ServiceAccept, Ok: false}
		} else {
			value.ServiceAccept = v2.ServiceAccept
			value.Ok = true
			(*m)[RequestOverSidecarKey{SidecarConnect: v2.SidecarConnect}] = value
			fmt.Println("assembled", value)
		}
	}
}

func updateMetric(vec *prometheus.SummaryVec, labels map[string]string, value float64) {
	if value < 0 {
		return
	}
	summary, err := vec.GetMetricWith(labels)
	if err == nil {
		summary.Observe(value)
	} else {
		fmt.Println(err)
	}
}

func updateCountMetric(vec *prometheus.CounterVec, labels map[string]string) {
	summary, err := vec.GetMetricWith(labels)
	if err == nil {
		summary.Inc()
	} else {
		fmt.Println(err)
	}
}

func GetRequestOverSidecarEvent(sidecarPidList []int, servicePidList []int, portList []int, podName string) {
	var pidList = append(sidecarPidList, servicePidList...)
	var protocolList []string

	processLabel := []string{"pid", "podName"}
	sidecarTime := visualization.GetNewSummaryVec("sidecar_process_request_duration", "", map[string]string{}, processLabel)
	sidecarToServiceTime := visualization.GetNewSummaryVec("sidecar_to_service_container_duration", "", map[string]string{}, processLabel)
	longConnectionCount := visualization.GetNewCounterVec("long_connection_counter", "", map[string]string{}, processLabel)
	prometheus.MustRegister(sidecarTime)
	prometheus.MustRegister(sidecarToServiceTime)
	prometheus.MustRegister(longConnectionCount)

	sidecarAcceptAndConnectEventPairMap := make(map[SidecarAcceptAndSidecarConnectKey]SidecarAcceptAndSidecarConnectValue)
	sidecarConnectAndServiceAcceptEventPairMap := make(map[SidecarConnectAndServiceAcceptKey]SidecarConnectAndServiceAcceptValue)
	RequestOverSidecarEventPairMap := make(map[RequestOverSidecarKey]RequestOverSidecarValue)

	acceptChan := make(chan tcpaccept.Event, 10000)
	go tcpaccept.Probe(pidList, portList, protocolList, acceptChan)
	connectChan := make(chan tcpconnect.Event, 10000)
	go tcpconnect.Probe(pidList, portList, protocolList, connectChan)

	for {
		select {
		case v1 := <-acceptChan:
			if slices.Contains(sidecarPidList, v1.Pid) { // got SidecarAcceptEvent
				fmt.Println("got SidecarAcceptEvent: ", v1)
				pair, ok := sidecarAcceptAndConnectEventPairMap[SidecarAcceptAndSidecarConnectKey{Pid: v1.Pid, Tid: v1.Tid}]
				if ok == false || (pair.Ok || pair.Ok == false && pair.SidecarConnect == sice) {
					if ok {
						updateCountMetric(longConnectionCount, map[string]string{"pid": strconv.Itoa(v1.Pid), "podName": podName})
					}
					sidecarAcceptAndConnectEventPairMap[SidecarAcceptAndSidecarConnectKey{Pid: v1.Pid, Tid: v1.Tid}] = SidecarAcceptAndSidecarConnectValue{SidecarAccept: SidecarAcceptEvent(v1), Ok: false}
				} else {
					pair.SidecarAccept = SidecarAcceptEvent(v1)
					pair.Ok = true
					sidecarAcceptAndConnectEventPairMap[SidecarAcceptAndSidecarConnectKey{Pid: v1.Pid, Tid: v1.Tid}] = pair
					fmt.Println("pair1", pair)
					fmt.Println("[DELTA sidecar]", (pair.SidecarConnect.Time - pair.SidecarAccept.Time).String())
					updateMetric(sidecarTime, map[string]string{"pid": strconv.Itoa(v1.Pid), "podName": podName}, float64(pair.SidecarConnect.Time-pair.SidecarAccept.Time))
					fillRequestOverSidecarField(&RequestOverSidecarEventPairMap, &pair, nil)
				}
				// fmt.Println("SidecarAcceptEvent done.")
			} else if slices.Contains(servicePidList, v1.Pid) { // got ServiceAcceptEvent
				fmt.Println("got ServiceAcceptEvent: ", v1)
				pair, ok := sidecarConnectAndServiceAcceptEventPairMap[SidecarConnectAndServiceAcceptKey{SidecarIp: v1.DAddr, SidecarPort: v1.DPort}]
				if ok == false || pair.Ok || (pair.Ok == false && pair.SidecarConnect == sice) {
					if ok { // never reaches here?
						updateCountMetric(longConnectionCount, map[string]string{"pid": strconv.Itoa(v1.Pid), "podName": podName})
					}
					sidecarConnectAndServiceAcceptEventPairMap[SidecarConnectAndServiceAcceptKey{SidecarIp: v1.DAddr, SidecarPort: v1.DPort}] = SidecarConnectAndServiceAcceptValue{ServiceAccept: ServiceAcceptEvent(v1), Ok: false}
				} else {
					pair.ServiceAccept = ServiceAcceptEvent(v1)
					pair.Ok = true
					sidecarConnectAndServiceAcceptEventPairMap[SidecarConnectAndServiceAcceptKey{SidecarIp: v1.DAddr, SidecarPort: v1.DPort}] = pair
					fmt.Println("pair2", pair)
					fmt.Println("[DELTA service]", (pair.ServiceAccept.Time - pair.SidecarConnect.Time).String())
					updateMetric(sidecarToServiceTime, map[string]string{"pid": strconv.Itoa(v1.Pid), "podName": podName}, float64(pair.ServiceAccept.Time-pair.SidecarConnect.Time))
					fillRequestOverSidecarField(&RequestOverSidecarEventPairMap, nil, &pair)
				}
				// fmt.Println("ServiceAcceptEvent done")
			} else {
				fmt.Println("You can not reach here. Ignoring accept event:", v1)
			}
		case v2 := <-connectChan:
			if slices.Contains(sidecarPidList, v2.Pid) { // got SidecarConnectEvent
				fmt.Println("got SidecarConnectEvent:", v2)
				// process sidecar accept and connect event
				pair1, ok := sidecarAcceptAndConnectEventPairMap[SidecarAcceptAndSidecarConnectKey{Pid: v2.Pid, Tid: v2.Tid}]
				if ok == false || pair1.Ok || (pair1.Ok == false && pair1.SidecarAccept == siae) {
					if ok {
						updateCountMetric(longConnectionCount, map[string]string{"pid": strconv.Itoa(v2.Pid), "podName": podName})
					}
					sidecarAcceptAndConnectEventPairMap[SidecarAcceptAndSidecarConnectKey{Pid: v2.Pid, Tid: v2.Tid}] = SidecarAcceptAndSidecarConnectValue{SidecarConnect: SidecarConnectEvent(v2), Ok: false}
				} else {
					pair1.SidecarConnect = SidecarConnectEvent(v2)
					pair1.Ok = true
					sidecarAcceptAndConnectEventPairMap[SidecarAcceptAndSidecarConnectKey{Pid: v2.Pid, Tid: v2.Tid}] = pair1
					fmt.Println("pair1: ", pair1)
					fmt.Println("[DELTA sidecar]", (pair1.SidecarConnect.Time - pair1.SidecarAccept.Time).String())
					updateMetric(sidecarTime, map[string]string{"pid": strconv.Itoa(v2.Pid), "podName": podName}, float64(pair1.SidecarConnect.Time-pair1.SidecarAccept.Time))
					fillRequestOverSidecarField(&RequestOverSidecarEventPairMap, &pair1, nil)
				}
				// process sidecar connect and service accept
				pair2, ok := sidecarConnectAndServiceAcceptEventPairMap[SidecarConnectAndServiceAcceptKey{SidecarIp: v2.SAddr, SidecarPort: v2.LPort}]
				if ok == false || pair2.Ok || (pair2.Ok == false && pair2.ServiceAccept == seae) {
					if ok { // never reaches here?
						updateCountMetric(longConnectionCount, map[string]string{"pid": strconv.Itoa(v2.Pid), "podName": podName})
					}
					sidecarConnectAndServiceAcceptEventPairMap[SidecarConnectAndServiceAcceptKey{SidecarIp: v2.SAddr, SidecarPort: v2.LPort}] = SidecarConnectAndServiceAcceptValue{SidecarConnect: SidecarConnectEvent(v2), Ok: false}
				} else {
					pair2.SidecarConnect = SidecarConnectEvent(v2)
					pair2.Ok = true
					sidecarConnectAndServiceAcceptEventPairMap[SidecarConnectAndServiceAcceptKey{SidecarIp: v2.SAddr, SidecarPort: v2.LPort}] = pair2
					fmt.Println("pair2: ", pair2)
					fmt.Println("[DELTA service]", (pair2.ServiceAccept.Time - pair2.SidecarConnect.Time).String())
					updateMetric(sidecarToServiceTime, map[string]string{"pid": strconv.Itoa(v2.Pid), "podName": podName}, float64(pair2.ServiceAccept.Time-pair2.SidecarConnect.Time))
					fillRequestOverSidecarField(&RequestOverSidecarEventPairMap, nil, &pair2)
				}
				// fmt.Println("SidecarConnectEvent done")
			} else {
				fmt.Println("You can not reach here. Ignoring connect event:", v2)
			}
		}
	}
}
