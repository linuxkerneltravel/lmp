package podnet

import (
	"bytes"
	_ "embed"
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"time"

	"github.com/iovisor/gobpf/bcc"

	"github.com/linuxkerneltravel/lmp/eBPF_Supermarket/sidecar/bpf"
	"github.com/linuxkerneltravel/lmp/eBPF_Supermarket/sidecar/tools"
)

import "C"

//go:embed podnet.c
var source string

const FUNCNAME_MAX_LEN = 64
const IFNAMSIZ = 16
const XT_TABLE_MAXNAMELEN = 32

type bpfEventData struct {
	TsNs uint64

	Pid uint32
	Tid uint32

	Comm     [16]byte
	FuncName [FUNCNAME_MAX_LEN]byte
	IfName   [IFNAMSIZ]byte

	SAddr tools.UnifiedAddress
	DAddr tools.UnifiedAddress

	Sport uint16
	Dport uint16
	Pad1  uint32

	Flags uint8
	Cpu   uint8
	Pad2  uint16
	NetNS uint32

	SkbAddress uint64 // (void*)

	// pkt info
	DestMac tools.Mac // 48 bit
	Pad3    uint16

	Len     uint32
	Ip      uint8
	L4Proto uint8
	TotLen  uint16

	TcpFlags uint16
	IcmpType uint8
	Pad4     uint8
	IcmPid   uint16
	IcmpSeq  uint16

	// ipt info
	Hook uint32
	Pf   uint8
	Pad5 uint8
	Pad6 uint16

	Verdict   uint32
	Pad7      uint32
	TableName [XT_TABLE_MAXNAMELEN]byte
	IptDelay  uint64

	// skb info
	PktType uint8
	Pad8    uint8
	Pad9    uint16
	// call stack
	KernelStackId uint32 // TODO: int map.get_stackid(void *ctx, u64 flags)

	KernelIp uint64
}

type Event struct {
	Time       time.Duration `json:"Time,omitempty"`
	NetNS      int
	Comm       string `json:"Comm"`
	IfName     string
	Pid        int `json:"pid"`
	Tid        int `json:"Tid"`
	SAddr      string
	DAddr      string
	Sport      int
	Dport      int
	SkbAddress string
	L4Proto    string
	TcpFlags   string
	Cpu        int

	Flags    uint8
	DestMac  string
	Len      int
	Ip       int
	TotLen   int
	IcmpType int
	IcmPid   int
	IcmpSeq  int

	// ipt info
	Hook      uint32
	Pf        uint8
	Verdict   uint32
	TableName string
	IptDelay  uint64

	// skb info
	PktType uint8

	// call stack
	KernelStackId uint32 // TODO: int map.get_stackid(void *ctx, u64 flags)
	KernelIp      uint64
	FuncName      string
}

func (e Event) Print() {
	// fmt.Println("╔======Pod net begin====╗")
	fmt.Println(e)
	// fmt.Println("╚======Pod net end======╝")
}

type EventList []Event

// Len is the number of elements in the collection.
func (el EventList) Len() int {
	return len(el)
}

// Less reports whether the element with
// index i should sort before the element with index j.
func (el EventList) Less(i, j int) bool {
	return el[i].Time < el[j].Time
}

// Swap swaps the elements with indexes i and j.
func (el EventList) Swap(i, j int) {
	e := el[i]
	el[i] = el[j]
	el[j] = e
}

func getEventFromBpfEventData(bpfEvent bpfEventData) Event {
	return Event{
		Time:          time.Duration(int64(bpfEvent.TsNs)),
		Comm:          strings.Trim(string(bpfEvent.Comm[:]), "\u0000"),
		Pid:           int(bpfEvent.Pid),
		Tid:           int(bpfEvent.Tid),
		FuncName:      strings.Trim(string(bpfEvent.FuncName[:]), "\u0000"),
		Flags:         bpfEvent.Flags,
		Cpu:           int(bpfEvent.Cpu),
		IfName:        strings.Trim(string(bpfEvent.IfName[:]), "\u0000"),
		NetNS:         int(bpfEvent.NetNS),
		DestMac:       bpfEvent.DestMac.ToString(),
		Len:           int(bpfEvent.Len),
		Ip:            int(bpfEvent.Ip),
		L4Proto:       bpf.GetProtocolFromInt(int(bpfEvent.L4Proto)),
		TotLen:        int(bpfEvent.TotLen),
		SAddr:         bpfEvent.SAddr.ToString(int(bpfEvent.Ip)),
		DAddr:         bpfEvent.DAddr.ToString(int(bpfEvent.Ip)),
		IcmpType:      int(bpfEvent.IcmpType),
		IcmPid:        int(bpfEvent.IcmPid),
		IcmpSeq:       int(bpfEvent.IcmpSeq),
		Sport:         int(bpfEvent.Sport),
		Dport:         int(bpfEvent.Dport),
		TcpFlags:      bpf.GetTcpFlags(int(bpfEvent.TcpFlags), true),
		Hook:          bpfEvent.Hook,
		Pf:            bpfEvent.Pf,
		Verdict:       bpfEvent.Verdict,
		TableName:     strings.Trim(string(bpfEvent.TableName[:]), "\u0000"),
		IptDelay:      bpfEvent.IptDelay,
		SkbAddress:    fmt.Sprintf("0x%x", bpfEvent.SkbAddress),
		PktType:       bpfEvent.PktType,
		KernelStackId: bpfEvent.KernelStackId,
		KernelIp:      bpfEvent.KernelIp,
	}
}

func contains(a []int, i int) bool {
	for _, v := range a {
		if v == i {
			return true
		}
	}
	return false
}

// Probe probes network events and pushes them out
func Probe(pidList []int, reverse bool, podIp string, ch chan<- Event) {
	pidFg := bpf.IntFilterGenerator{Name: "pid", List: pidList, Action: "return 0;", Reverse: reverse}
	ipFilter := ""
	ipRep := ""
	if podIp != "" {
		ipAdd := net.ParseIP(podIp)
		if ipAdd.To4() != nil { // IPv4
			ipFilter = "/*FILTER_IPV4*/"
			ipv4Int, _ := tools.IpToUint32(podIp)
			ipRep = "if(iphdr.saddr != " + strconv.Itoa(int(ipv4Int)) + " && iphdr.daddr != " + strconv.Itoa(int(ipv4Int)) + ") return -1;"
		} else if ipAdd.To16() != nil { // IPv6
			ipFilter = "/*FILTER_IPV6*/"
			ipRep = "" // TODO
		}
	}

	sourceBpf := source
	sourceBpf = strings.Replace(sourceBpf, "/*FILTER_PID*/", pidFg.Generate(), 1)

	if ipFilter != "" {
		sourceBpf = strings.Replace(sourceBpf, ipFilter, ipRep, 1)
	}

	m := bcc.NewModule(sourceBpf, []string{})
	defer m.Close()

	// 5 netif rcv hooks:
	bpf.AttachKprobe(m, "kprobe__netif_rx", "netif_rx")
	bpf.AttachKprobe(m, "kprobe____netif_receive_skb", "netif_receive_skb")
	bpf.AttachKprobe(m, "kprobe__tpacket_rcv", "tpacket_rcv")
	bpf.AttachKprobe(m, "kprobe__packet_rcv", "packet_rcv")
	bpf.AttachKprobe(m, "kprobe__napi_gro_receive", "napi_gro_receive")

	// 1 netif send hook:
	bpf.AttachKprobe(m, "kprobe____dev_queue_xmit", "__dev_queue_xmit")

	// 14 br process hooks:
	// bpf.AttachKprobe(m, "kprobe__br_handle_frame", "br_handle_frame")
	// bpf.AttachKprobe(m, "kprobe__br_handle_frame_finish", "br_handle_frame_finish")
	// bpf.AttachKprobe(m, "kprobe__br_nf_pre_routing", "br_nf_pre_routing")
	// bpf.AttachKprobe(m, "kprobe__br_nf_pre_routing_finish", "br_nf_pre_routing_finish")
	// bpf.AttachKprobe(m, "kprobe__br_pass_frame_up", "br_pass_frame_up")
	// bpf.AttachKprobe(m, "kprobe__br_netif_receive_skb", "br_netif_receive_skb")
	// bpf.AttachKprobe(m, "kprobe__br_forward", "br_forward")
	// bpf.AttachKprobe(m, "kprobe____br_forward", "__br_forward")
	// bpf.AttachKprobe(m, "kprobe__deliver_clone", "deliver_clone")
	// bpf.AttachKprobe(m, "kprobe__br_forward_finish", "br_forward_finish")
	// bpf.AttachKprobe(m, "kprobe__br_nf_forward_ip", "br_nf_forward_ip")
	// bpf.AttachKprobe(m, "kprobe__br_nf_forward_finish", "br_nf_forward_finish")
	// bpf.AttachKprobe(m, "kprobe__br_nf_post_routing", "br_nf_post_routing")
	// bpf.AttachKprobe(m, "kprobe__br_nf_dev_queue_xmit", "br_nf_dev_queue_xmit")

	// 4 ip layer hooks:
	bpf.AttachKprobe(m, "kprobe__ip_rcv", "ip_rcv")
	bpf.AttachKprobe(m, "kprobe__ip_rcv_finish", "ip_rcv_finish")
	bpf.AttachKprobe(m, "kprobe__ip_output", "ip_output")
	bpf.AttachKprobe(m, "kprobe__ip_finish_output", "ip_finish_output")

	table := bcc.NewTable(m.TableId("route_event"), m)

	channel := make(chan []byte, 1000)
	perfMap, err := bcc.InitPerfMap(table, channel, nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to init perf map: %s\n", err)
		os.Exit(1)
	}

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, os.Kill)

	fmt.Println("Deep pod net started!")
	go func() {
		for {
			data := <-channel
			var event bpfEventData
			err := binary.Read(bytes.NewBuffer(data), bcc.GetHostByteOrder(), &event)
			if err != nil {
				fmt.Printf("failed to decode received data: %s\n", err)
				continue
			}

			goEvent := getEventFromBpfEventData(event)
			goEvent.Print()
			ch <- goEvent
		}
	}()

	perfMap.Start()
	<-sig
	perfMap.Stop()
}

// Sample provides a no argument function call
func Sample() {
	var pidList []int
	ipAdd := ""
	ch := make(chan Event, 10000)

	go Probe(pidList, false, ipAdd, ch)

	for {
		event := <-ch
		event.Print()
	}
}
