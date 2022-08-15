package tcpclose

import (
	"bytes"
	"encoding/binary"
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
// ver: 9d06ced06f63161570d5fb6376acf099225899a3
#include <uapi/linux/ptrace.h>
#include <linux/tcp.h>
#include <net/sock.h>
#include <bcc/proto.h>
BPF_HASH(birth, struct sock *, u64);
// separate data structs for ipv4 and ipv6
struct ipv4_data_t {
    u64 ts_ns;
    u32 pid;
	u32 tid;
    u32 saddr;
    u32 daddr;
    u16 lport;
    u16 dport;
	u32 pad;
    u64 rx_b;
    u64 tx_b;
    u64 span_ns;
    char task[TASK_COMM_LEN];
};
BPF_PERF_OUTPUT(ipv4_events);
struct ipv6_data_t {
    u64 ts_ns;
    u32 pid;
	u32 tid;
    unsigned __int128 saddr;
    unsigned __int128 daddr;
    u16 lport;
    u16 dport;
	u32 pad;
    u64 rx_b;
    u64 tx_b;
    u64 span_ns;
    char task[TASK_COMM_LEN];
};
BPF_PERF_OUTPUT(ipv6_events);
struct id_t {
    u32 pid;
	u32 tid;
    char task[TASK_COMM_LEN];
};
BPF_HASH(whoami, struct sock *, struct id_t);
`

const sourceKprobe string = `
int kprobe__tcp_set_state(struct pt_regs *ctx, struct sock *sk, int state)
{
	u64 pid_tgid = bpf_get_current_pid_tgid();
	u32 pid = pid_tgid >> 32;
	u32 tid = pid_tgid;

    // lport is either used in a filter here, or later
    u16 lport = sk->__sk_common.skc_num;
    /*FILTER_LPORT*/
    // dport is either used in a filter here, or later
    u16 dport = sk->__sk_common.skc_dport;
    dport = ntohs(dport);
    /*FILTER_DPORT*/

    /*
     * This tool includes PID and comm context. It's best effort, and may
     * be wrong in some situations. It currently works like this:
     * - record timestamp on any state < TCP_FIN_WAIT1
     * - cache task context on:
     *       TCP_SYN_SENT: tracing from client
     *       TCP_LAST_ACK: client-closed from server
     * - do output on TCP_CLOSE:
     *       fetch task context if cached, or use current task
     */
    // capture birth time
    if (state < TCP_FIN_WAIT1) {
        /*
         * Matching just ESTABLISHED may be sufficient, provided no code-path
         * sets ESTABLISHED without a tcp_set_state() call. Until we know
         * that for sure, match all early states to increase chances a
         * timestamp is set.
         * Note that this needs to be set before the PID filter later on,
         * since the PID isn't reliable for these early stages, so we must
         * save all timestamps and do the PID filter later when we can.
         */
        u64 ts = bpf_ktime_get_ns();
        birth.update(&sk, &ts);
    }
    // record PID & comm on SYN_SENT
    if (state == TCP_SYN_SENT || state == TCP_LAST_ACK) {
        // now we can PID filter, both here and a little later on for CLOSE
        /*FILTER_PID*/
        struct id_t me = {.pid = pid, .tid = tid};
        bpf_get_current_comm(&me.task, sizeof(me.task));
        whoami.update(&sk, &me);
    }
    if (state != TCP_CLOSE)
        return 0;
    // calculate lifespan
    u64 *tsp, delta_ns;
    tsp = birth.lookup(&sk);
    if (tsp == 0) {
        whoami.delete(&sk);     // may not exist
        return 0;               // missed create
    }
    delta_ns = bpf_ktime_get_ns() - *tsp;
    birth.delete(&sk);

    // fetch possible cached data, and filter
    struct id_t *mep;
    mep = whoami.lookup(&sk);
    if (mep != 0) {
		pid = mep->pid;
		tid = mep->tid;
	}
    /*FILTER_PID*/

    // get throughput stats. see tcp_get_info().
    u64 rx_b = 0, tx_b = 0;
    struct tcp_sock *tp = (struct tcp_sock *)sk;
    rx_b = tp->bytes_received;
    tx_b = tp->bytes_acked;

    u16 family = sk->__sk_common.skc_family;
    /*FILTER_FAMILY*/

    if (family == AF_INET) {
        struct ipv4_data_t data4 = {};
        data4.rx_b = rx_b;
        data4.tx_b = tx_b;
        data4.ts_ns = bpf_ktime_get_ns();
        data4.saddr = sk->__sk_common.skc_rcv_saddr;
        data4.daddr = sk->__sk_common.skc_daddr;
        data4.pid = pid;
		data4.tid = tid;
		data4.lport = lport;
		data4.dport = dport;
        data4.span_ns = delta_ns;
        if (mep == 0) {
            bpf_get_current_comm(&data4.task, sizeof(data4.task));
        } else {
            bpf_probe_read_kernel(&data4.task, sizeof(data4.task), (void *)mep->task);
        }
        ipv4_events.perf_submit(ctx, &data4, sizeof(data4));
    } else /* 6 */ {
        struct ipv6_data_t data6 = {};
        data6.rx_b = rx_b;
        data6.tx_b = tx_b;
        data6.ts_ns = bpf_ktime_get_ns() / 1000;
        bpf_probe_read_kernel(&data6.saddr, sizeof(data6.saddr), sk->__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32);
        bpf_probe_read_kernel(&data6.daddr, sizeof(data6.daddr), sk->__sk_common.skc_v6_daddr.in6_u.u6_addr32);
        data6.pid = pid;
		data6.tid = tid;
		data6.lport = lport;
		data6.dport = dport;
        data6.span_ns = delta_ns;
        if (mep == 0) {
            bpf_get_current_comm(&data6.task, sizeof(data6.task));
        } else {
            bpf_probe_read_kernel(&data6.task, sizeof(data6.task), (void *)mep->task);
        }
        ipv6_events.perf_submit(ctx, &data6, sizeof(data6));
    }
    if (mep != 0)
        whoami.delete(&sk);
    return 0;
}
`

const sourceTracepoint string = `
TRACEPOINT_PROBE(sock, inet_sock_set_state)
{
    if (args->protocol != IPPROTO_TCP)
        return 0;

	u64 pid_tgid = bpf_get_current_pid_tgid();
	u32 pid = pid_tgid >> 32;
	u32 tid = pid_tgid;

    // sk is mostly used as a UUID, and for two tcp stats:
    struct sock *sk = (struct sock *)args->skaddr;

    // lport is either used in a filter here, or later
    u16 lport = args->sport;
	/*FILTER_LPORT*/
    
	// dport is either used in a filter here, or later
    u16 dport = args->dport;
    /*FILTER_DPORT*/
    
	/*
     * This tool includes PID and comm context. It's best effort, and may
     * be wrong in some situations. It currently works like this:
     * - record timestamp on any state < TCP_FIN_WAIT1
     * - cache task context on:
     *       TCP_SYN_SENT: tracing from client
     *       TCP_LAST_ACK: client-closed from server
     * - do output on TCP_CLOSE:
     *       fetch task context if cached, or use current task
     */
    // capture birth time
    if (args->newstate < TCP_FIN_WAIT1) {
        /*
         * Matching just ESTABLISHED may be sufficient, provided no code-path
         * sets ESTABLISHED without a tcp_set_state() call. Until we know
         * that for sure, match all early states to increase chances a
         * timestamp is set.
         * Note that this needs to be set before the PID filter later on,
         * since the PID isn't reliable for these early stages, so we must
         * save all timestamps and do the PID filter later when we can.
         */
        u64 ts = bpf_ktime_get_ns();
        birth.update(&sk, &ts);
    }
    // record PID & comm on SYN_SENT
    if (args->newstate == TCP_SYN_SENT || args->newstate == TCP_LAST_ACK) {
        // now we can PID filter, both here and a little later on for CLOSE
        /*FILTER_PID*/
        struct id_t me = {.pid = pid, .tid = tid};
        bpf_get_current_comm(&me.task, sizeof(me.task));
        whoami.update(&sk, &me);
    }
    if (args->newstate != TCP_CLOSE)
        return 0;
    // calculate lifespan
    u64 *tsp, delta_ns;
    tsp = birth.lookup(&sk);
    if (tsp == 0) {
        whoami.delete(&sk);     // may not exist
        return 0;               // missed create
    }
    delta_ns = bpf_ktime_get_ns() - *tsp;
    birth.delete(&sk);
    
	// fetch possible cached data, and filter
    struct id_t *mep;
    mep = whoami.lookup(&sk);
    if (mep != 0) {
		pid = mep->pid;
		tid = mep->tid;
	}
    /*FILTER_PID*/

    u16 family = args->family;
    /*FILTER_FAMILY*/

    // get throughput stats. see tcp_get_info().
    u64 rx_b = 0, tx_b = 0;
    struct tcp_sock *tp = (struct tcp_sock *)sk;
    rx_b = tp->bytes_received;
    tx_b = tp->bytes_acked;
    if (args->family == AF_INET) {
        struct ipv4_data_t data4 = {};
        data4.rx_b = rx_b;
        data4.tx_b = tx_b;
        data4.ts_ns = bpf_ktime_get_ns();
        __builtin_memcpy(&data4.saddr, args->saddr, sizeof(data4.saddr));
        __builtin_memcpy(&data4.daddr, args->daddr, sizeof(data4.daddr));
        data4.pid = pid;
		data4.tid = tid;
		data4.lport = lport;
		data4.dport = dport;
        data4.span_ns = delta_ns;
        if (mep == 0) {
            bpf_get_current_comm(&data4.task, sizeof(data4.task));
        } else {
            bpf_probe_read_kernel(&data4.task, sizeof(data4.task), (void *)mep->task);
        }
        ipv4_events.perf_submit(args, &data4, sizeof(data4));
    } else /* 6 */ {
        struct ipv6_data_t data6 = {};
        data6.rx_b = rx_b;
        data6.tx_b = tx_b;
        data6.ts_ns = bpf_ktime_get_ns();
        __builtin_memcpy(&data6.saddr, args->saddr_v6, sizeof(data6.saddr));
        __builtin_memcpy(&data6.daddr, args->daddr_v6, sizeof(data6.daddr));
        data6.pid = pid;
		data6.tid = tid;
		data6.lport = lport;
		data6.dport = dport;
        data6.span_ns = delta_ns;
        if (mep == 0) {
            bpf_get_current_comm(&data6.task, sizeof(data6.task));
        } else {
            bpf_probe_read_kernel(&data6.task, sizeof(data6.task), (void *)mep->task);
        }
        ipv6_events.perf_submit(args, &data6, sizeof(data6));
    }
    if (mep != 0)
        whoami.delete(&sk);
    return 0;
}
`

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

	sourceBpf := source
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
