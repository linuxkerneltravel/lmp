package tcpclose

import (
	"bytes"
	_ "embed"
	"encoding/binary"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"time"

	"github.com/iovisor/gobpf/bcc"

	"github.com/linuxkerneltravel/lmp/eBPF_Supermarket/sidecar/bpf"
	"github.com/linuxkerneltravel/lmp/eBPF_Supermarket/sidecar/tools"
)

import "C"

//go:embed tcpclose_define.c
var sourceDefine string

//go:embed tcpclose_kprobe.c
var sourceKprobe string

//go:embed tcpclose_tracepoint.c
var sourceTracepoint string

type ipv4EventData struct {
	TsNs   uint64
	Pid    uint32
	Tid    uint32
	SAddr  tools.Ipv4Address
	DAddr  tools.Ipv4Address
	LPort  uint16
	DPort  uint16
	Pad    uint32
	RxB    uint64
	TxB    uint64
	SpanUs uint64
	Comm   [16]byte
}

type ipv6EventData struct {
	TsNs   uint64
	Pid    uint32
	Tid    uint32
	SAddr  tools.Ipv6Address
	DAddr  tools.Ipv6Address
	LPort  uint16
	DPort  uint16
	Pad    uint32
	RxB    uint64
	TxB    uint64
	SpanUs uint64
	Comm   [16]byte
}

type Event struct {
	Time  time.Duration `json:"Time,omitempty"`
	Comm  string        `json:"Comm"`
	Pid   int           `json:"pid"`
	Tid   int           `json:"Tid"`
	SAddr string        `json:"SAddr"`
	DAddr string        `json:"DAddr"`
	LPort int           `json:"LPort"`
	DPort int           `json:"DPort"`
	RxB   int           `json:"RxB"`
	TxB   int           `json:"TxB"`
	Span  time.Duration `json:"Span"`
	Ip    int           `json:"Ip"`
}

func (e Event) Print() {
	fmt.Println("╔======TCP connect begin====╗")
	fmt.Println("Time :", e.Time.String())
	fmt.Println("Comm :", e.Comm)
	fmt.Println("Pid  :", e.Pid)
	fmt.Println("Tid  :", e.Tid)
	fmt.Println("SAddr:", e.SAddr)
	fmt.Println("DAddr:", e.DAddr)
	fmt.Println("LPort:", e.LPort)
	fmt.Println("DPort:", e.DPort)
	fmt.Println("RxB  :", e.RxB)
	fmt.Println("TxB  :", e.TxB)
	fmt.Println("Span :", e.Span.String())
	fmt.Println("Ip   :", e.Ip)
	fmt.Println("╚======TCP connect end======╝")
}

func getEventFromIpv4EventData(bpfEvent ipv4EventData) Event {
	return Event{
		Time:  time.Duration(int64(bpfEvent.TsNs)),
		Comm:  strings.Trim(string(bpfEvent.Comm[:]), "\u0000"),
		Pid:   int(bpfEvent.Pid),
		Tid:   int(bpfEvent.Tid),
		SAddr: bpfEvent.SAddr.ToString(),
		DAddr: bpfEvent.DAddr.ToString(),
		LPort: int(bpfEvent.LPort),
		DPort: int(bpfEvent.DPort),
		RxB:   int(bpfEvent.RxB),
		TxB:   int(bpfEvent.TxB),
		Span:  time.Duration(int64(bpfEvent.SpanUs)),
		Ip:    4,
	}
}

func getEventFromIpv6EventData(bpfEvent ipv6EventData) Event {
	return Event{
		Time:  time.Duration(int64(bpfEvent.TsNs)),
		Comm:  strings.Trim(string(bpfEvent.Comm[:]), "\u0000"),
		Pid:   int(bpfEvent.Pid),
		Tid:   int(bpfEvent.Tid),
		SAddr: bpfEvent.SAddr.ToString(),
		DAddr: bpfEvent.DAddr.ToString(),
		LPort: int(bpfEvent.LPort),
		DPort: int(bpfEvent.DPort),
		RxB:   int(bpfEvent.RxB),
		TxB:   int(bpfEvent.TxB),
		Span:  time.Duration(int64(bpfEvent.SpanUs)),
		Ip:    6,
	}
}

// Probe probes TCP close event and pushes it out
func Probe(pidList []int, portList []int, protocolList []string, ch chan<- Event) {
	pidFg := bpf.IntFilterGenerator{Name: "pid", List: pidList, Action: "return 0;", Reverse: false}
	lportFg := bpf.IntFilterGenerator{Name: "lport", List: portList, Action: "birth.delete(&sk); return 0;", Reverse: false}
	dportFg := bpf.IntFilterGenerator{Name: "dport", List: portList, Action: "birth.delete(&sk); return 0;", Reverse: false}
	familyFg := bpf.FamilyFilterGenerator{List: protocolList}

	sourceBpf := sourceDefine
	if bpf.TracepointExists("sock", "inet_sock_set_state") {
		sourceBpf += sourceTracepoint
	} else {
		sourceBpf += sourceKprobe
	}

	sourceBpf = strings.Replace(sourceBpf, "/*FILTER_PID*/", pidFg.Generate(), 1)
	sourceBpf = strings.Replace(sourceBpf, "/*FILTER_LPORT*/", lportFg.Generate(), 1)
	sourceBpf = strings.Replace(sourceBpf, "/*FILTER_DPORT*/", dportFg.Generate(), 1)
	sourceBpf = strings.Replace(sourceBpf, "/*FILTER_FAMILY*/", familyFg.Generate(), 1)

	m := bcc.NewModule(sourceBpf, []string{})
	defer m.Close()

	if bpf.TracepointExists("sock", "inet_sock_set_state") {
		bpf.AttachTracepoint(m, "tracepoint__sock__inet_sock_set_state", "sock:inet_sock_set_state")
	} else {
		bpf.AttachKprobe(m, "kprobe__tcp_set_state", "tcp_set_state")
	}

	tablev4 := bcc.NewTable(m.TableId("ipv4_events"), m)
	channelv4 := make(chan []byte, 1000)
	perfMapv4, err := bcc.InitPerfMap(tablev4, channelv4, nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to init perf map: %s\n", err)
		os.Exit(1)
	}

	tablev6 := bcc.NewTable(m.TableId("ipv6_events"), m)
	channelv6 := make(chan []byte, 1000)
	perfMapv6, err := bcc.InitPerfMap(tablev6, channelv6, nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to init perf map: %s\n", err)
		os.Exit(1)
	}

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, os.Kill)

	fmt.Println("TCP close started!")
	go func() {
		for {
			data := <-channelv4
			var event ipv4EventData
			err := binary.Read(bytes.NewBuffer(data), bcc.GetHostByteOrder(), &event)
			if err != nil {
				fmt.Printf("failed to decode received data: %s\n", err)
				continue
			}
			goEvent := getEventFromIpv4EventData(event)
			ch <- goEvent
		}
	}()

	go func() {
		for {
			data := <-channelv6
			var event ipv6EventData
			err := binary.Read(bytes.NewBuffer(data), bcc.GetHostByteOrder(), &event)
			if err != nil {
				fmt.Printf("failed to decode received data: %s\n", err)
				continue
			}
			goEvent := getEventFromIpv6EventData(event)
			ch <- goEvent
		}
	}()

	perfMapv4.Start()
	perfMapv6.Start()
	<-sig
	perfMapv4.Stop()
	perfMapv6.Stop()
}

// Sample provides a no argument function call
func Sample() {
	var pidList []int
	var portList []int
	var protocolList []string
	ch := make(chan Event, 10000)

	go Probe(pidList, portList, protocolList, ch)

	for {
		event := <-ch
		event.Print()
	}
}
