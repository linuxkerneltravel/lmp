package tcpconnect

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"time"

	"github.com/iovisor/gobpf/bcc"

	"github.com/eswzy/podstat/bpf"
	"github.com/eswzy/podstat/tools"
)

import "C"

const source string = `
#include <uapi/linux/ptrace.h>
#include <net/sock.h>
#include <bcc/proto.h>
BPF_HASH(currsock, u32, struct sock *);
// separate data structs for ipv4 and ipv6
struct ipv4_data_t {
    u64 ts_us;
    u32 pid;
    u32 tid;
    u32 saddr;
    u32 daddr;
    u64 ip;
    u16 lport;
    u16 dport;
    char task[TASK_COMM_LEN];
};
BPF_PERF_OUTPUT(ipv4_events);
struct ipv6_data_t {
    u64 ts_us;
    u32 pid;
    u32 tid;
    unsigned __int128 saddr;
    unsigned __int128 daddr;
    u64 ip;
    u16 lport;
    u16 dport;
    char task[TASK_COMM_LEN];
};
BPF_PERF_OUTPUT(ipv6_events);

int trace_connect_entry(struct pt_regs *ctx, struct sock *sk)
{
    // if (container_should_be_filtered()) {
    //     return 0;
    // }
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    u32 tid = pid_tgid;
    /*FILTER_PID*/

    // stash the sock ptr for lookup on return
    currsock.update(&tid, &sk);
    return 0;
};

static int trace_connect_return(struct pt_regs *ctx, short family)
{
    int ret = PT_REGS_RC(ctx);
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    u32 tid = pid_tgid;
    struct sock **skpp;
    skpp = currsock.lookup(&tid);
    if (skpp == 0) {
        return 0;   // missed entry
    }
    if (ret != 0) {
        // failed to send SYNC packet, may not have populated
        // socket __sk_common.{skc_rcv_saddr, ...}
        currsock.delete(&tid);
        return 0;
    }
    // pull in details
    struct sock *skp = *skpp;
    u16 lport = skp->__sk_common.skc_num;
    u16 dport = skp->__sk_common.skc_dport;
    /*FILTER_PORT*/
    /*FILTER_FAMILY*/
    if (family == 4) {
        struct ipv4_data_t data4 = {.pid = pid, .ip = family};
      data4.tid = tid;
	    data4.ts_us = bpf_ktime_get_ns() / 1000;
	    data4.saddr = skp->__sk_common.skc_rcv_saddr;
	    data4.daddr = skp->__sk_common.skc_daddr;
	    data4.lport = lport;
	    data4.dport = ntohs(dport);
	    bpf_get_current_comm(&data4.task, sizeof(data4.task));
	    ipv4_events.perf_submit(ctx, &data4, sizeof(data4));
    } else /* 6 */ {
	    struct ipv6_data_t data6 = {.pid = pid, .ip = family};
        data6.tid = tid;
	    data6.ts_us = bpf_ktime_get_ns() / 1000;
	    bpf_probe_read_kernel(&data6.saddr, sizeof(data6.saddr), skp->__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32);
	    bpf_probe_read_kernel(&data6.daddr, sizeof(data6.daddr), skp->__sk_common.skc_v6_daddr.in6_u.u6_addr32);
	    data6.lport = lport;
	    data6.dport = ntohs(dport);
	    bpf_get_current_comm(&data6.task, sizeof(data6.task));
	    ipv6_events.perf_submit(ctx, &data6, sizeof(data6));
    }
    currsock.delete(&tid);
    return 0;
}
int trace_connect_v4_return(struct pt_regs *ctx)
{
    return trace_connect_return(ctx, 4);
}
int trace_connect_v6_return(struct pt_regs *ctx)
{
    return trace_connect_return(ctx, 6);
}
`

type ipv4EventData struct {
	TsUs  uint64
	Pid   uint32
	Tid   uint32
	SAddr tools.Ipv4Address
	DAddr tools.Ipv4Address
	Ip    uint64
	LPort uint16
	DPort uint16
	Comm  [16]byte
}

type ipv6EventData struct {
	TsUs  uint64
	Pid   uint32
	Tid   uint32
	SAddr tools.Ipv6Address
	DAddr tools.Ipv6Address
	Ip    uint64
	LPort uint16
	DPort uint16
	Comm  [16]byte
}

type Event struct {
	Time  time.Time `json:"time,omitempty"`
	Comm  string    `json:"comm"`
	Pid   int       `json:"pid"`
	Tid   int       `json:"Tid"`
	SAddr string    `json:"SAddr"`
	DAddr string    `json:"DAddr"`
	LPort int       `json:"LPort"`
	DPort int       `json:"DPort"`
	Ip    int       `json:"Ip"`
}

func getEventFromIpv4EventData(bpfEvent ipv4EventData) Event {
	return Event{
		Time:  time.UnixMicro(int64(bpfEvent.TsUs)),
		Comm:  strings.Trim(string(bpfEvent.Comm[:]), "\u0000"),
		Pid:   int(bpfEvent.Pid),
		Tid:   int(bpfEvent.Tid),
		SAddr: bpfEvent.SAddr.ToString(),
		DAddr: bpfEvent.DAddr.ToString(),
		LPort: int(bpfEvent.LPort),
		DPort: int(bpfEvent.DPort),
		Ip:    int(bpfEvent.Ip),
	}
}

func getTcpEventFromIpv6EventData(bpfEvent ipv6EventData) Event {
	return Event{
		Time:  time.UnixMicro(int64(bpfEvent.TsUs)),
		Comm:  strings.Trim(string(bpfEvent.Comm[:]), "\u0000"),
		Pid:   int(bpfEvent.Pid),
		Tid:   int(bpfEvent.Tid),
		SAddr: bpfEvent.SAddr.ToString(),
		DAddr: bpfEvent.DAddr.ToString(),
		LPort: int(bpfEvent.LPort),
		DPort: int(bpfEvent.DPort),
		Ip:    int(bpfEvent.Ip),
	}
}

// TcpConnect probes TCP connect event and pushes it out
func TcpConnect(pidList []int, portList []int, protocolList []string, ch chan<- Event) {
	fmt.Println("TcpConnect started!")
	pidFg := bpf.IntFilterGenerator{Name: "pid", List: pidList, Reverse: false}
	portFg := bpf.IntFilterGenerator{Name: "dport", List: portList, Reverse: false}
	familyFg := bpf.FamilyFilterGenerator{List: protocolList}

	sourceBpf := source
	sourceBpf = strings.Replace(sourceBpf, "/*FILTER_PID*/", pidFg.Generate(), 1)
	sourceBpf = strings.Replace(sourceBpf, "/*FILTER_PORT*/", portFg.Generate(), 1)
	sourceBpf = strings.Replace(sourceBpf, "/*FILTER_FAMILY*/", familyFg.Generate(), 1)

	m := bcc.NewModule(sourceBpf, []string{})
	defer m.Close()

	bpf.AttachKprobe(m, "trace_connect_entry", "tcp_v4_connect")
	bpf.AttachKprobe(m, "trace_connect_entry", "tcp_v6_connect")
	bpf.AttachKretprobe(m, "trace_connect_v4_return", "tcp_v4_connect")
	bpf.AttachKretprobe(m, "trace_connect_v6_return", "tcp_v6_connect")

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
			goEvent := getTcpEventFromIpv6EventData(event)
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

	go TcpConnect(pidList, portList, protocolList, ch)

	for {
		event := <-ch
		jsonEvent, _ := json.MarshalIndent(event, "", "  ")
		fmt.Println(string(jsonEvent))
	}
}
