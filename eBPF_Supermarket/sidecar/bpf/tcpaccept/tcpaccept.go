package tcpaccept

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

// The following code uses kprobes to instrument inet_csk_accept().
// On Linux 4.16 and later, we could use sock:inet_sock_set_state
// tracepoint for efficiency, but it may output wrong PIDs. This is
// because sock:inet_sock_set_state may run outside of process context.
// Hence, we stick to kprobes until we find a proper solution.

int kretprobe__inet_csk_accept(struct pt_regs *ctx)
{
  //if (container_should_be_filtered()) {
  //    return 0;
  //}
  struct sock *newsk = (struct sock *)PT_REGS_RC(ctx);
  u64 pid_tgid = bpf_get_current_pid_tgid();
  u32 pid = pid_tgid >> 32;
  u32 tid = pid_tgid;
  
  /*FILTER_PID*/
  
  if (newsk == NULL)
      return 0;
  // check this is TCP
  u16 protocol = 0;
  // workaround for reading the sk_protocol bitfield:
  // Following comments add by Joe Yin:
  // Unfortunately,it can not work since Linux 4.10,
  // because the sk_wmem_queued is not following the bitfield of sk_protocol.
  // And the following member is sk_gso_max_segs.
  // So, we can use this:
  // bpf_probe_read_kernel(&protocol, 1, (void *)((u64)&newsk->sk_gso_max_segs) - 3);
  // In order to  diff the pre-4.10 and 4.10+ ,introduce the variables gso_max_segs_offset,sk_lingertime,
  // sk_lingertime is closed to the gso_max_segs_offset,and
  // the offset between the two members is 4
  int gso_max_segs_offset = offsetof(struct sock, sk_gso_max_segs);
  int sk_lingertime_offset = offsetof(struct sock, sk_lingertime);
  // Since kernel v5.6 sk_protocol is its own u16 field and gso_max_segs
  // precedes sk_lingertime.
  if (sk_lingertime_offset - gso_max_segs_offset == 2)
      protocol = newsk->sk_protocol;
  else if (sk_lingertime_offset - gso_max_segs_offset == 4)
      // 4.10+ with little endian
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
      protocol = *(u8 *)((u64)&newsk->sk_gso_max_segs - 3);
  else
      // pre-4.10 with little endian
      protocol = *(u8 *)((u64)&newsk->sk_wmem_queued - 3);
#elif __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
      // 4.10+ with big endian
      protocol = *(u8 *)((u64)&newsk->sk_gso_max_segs - 1);
  else
      // pre-4.10 with big endian
      protocol = *(u8 *)((u64)&newsk->sk_wmem_queued - 1);
#else
# error "Fix your compiler's __BYTE_ORDER__?!"
#endif
  if (protocol != IPPROTO_TCP)
      return 0;
  // pull in details
  u16 family = 0, lport = 0, dport;
  family = newsk->__sk_common.skc_family;
  lport = newsk->__sk_common.skc_num;
  dport = newsk->__sk_common.skc_dport;
  dport = ntohs(dport);
  
  /*FILTER_FAMILY*/
  /*FILTER_PORT*/
  
  if (family == AF_INET) {
      struct ipv4_data_t data4 = {.pid = pid, .ip = 4};
      data4.tid = tid;
      data4.ts_us = bpf_ktime_get_ns() / 1000;
      data4.saddr = newsk->__sk_common.skc_rcv_saddr;
      data4.daddr = newsk->__sk_common.skc_daddr;
      data4.lport = lport;
      data4.dport = dport;
      bpf_get_current_comm(&data4.task, sizeof(data4.task));
      ipv4_events.perf_submit(ctx, &data4, sizeof(data4));
  } else if (family == AF_INET6) {
      struct ipv6_data_t data6 = {.pid = pid, .ip = 6};
      data6.tid = tid;
      data6.ts_us = bpf_ktime_get_ns() / 1000;
      bpf_probe_read_kernel(&data6.saddr, sizeof(data6.saddr), &newsk->__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32);
      bpf_probe_read_kernel(&data6.daddr, sizeof(data6.daddr), &newsk->__sk_common.skc_v6_daddr.in6_u.u6_addr32);
      data6.lport = lport;
      data6.dport = dport;
      bpf_get_current_comm(&data6.task, sizeof(data6.task));
      ipv6_events.perf_submit(ctx, &data6, sizeof(data6));
  }
  // else drop
  return 0;
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

func getTcpAcceptEventFromIpv4EventData(bpfEvent ipv4EventData) Event {
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

func getTcpAcceptEventFromIpv6EventData(bpfEvent ipv6EventData) Event {
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

// TcpAccept probes TCP accept event and pushes it out
func TcpAccept(pidList []int, portList []int, protocolList []string, ch chan<- Event) {
	fmt.Println("TcpAccept started!")
	pidFg := bpf.IntFilterGenerator{Name: "pid", List: pidList, Reverse: false}
	portFg := bpf.IntFilterGenerator{Name: "lport", List: portList, Reverse: false}
	familyFg := bpf.FamilyFilterGenerator{List: protocolList}

	sourceBpf := source
	sourceBpf = strings.Replace(sourceBpf, "/*FILTER_PID*/", pidFg.Generate(), 1)
	sourceBpf = strings.Replace(sourceBpf, "/*FILTER_PORT*/", portFg.Generate(), 1)
	sourceBpf = strings.Replace(sourceBpf, "/*FILTER_FAMILY*/", familyFg.Generate(), 1)

	m := bcc.NewModule(sourceBpf, []string{})
	defer m.Close()

	bpf.AttachKretprobe(m, "kretprobe__inet_csk_accept", "inet_csk_accept")

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
			goEvent := getTcpAcceptEventFromIpv4EventData(event)
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
			goEvent := getTcpAcceptEventFromIpv6EventData(event)
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

	go TcpAccept(pidList, portList, protocolList, ch)

	for {
		event := <-ch
		jsonEvent, _ := json.MarshalIndent(event, "", "  ")
		fmt.Println(string(jsonEvent))
	}
}
