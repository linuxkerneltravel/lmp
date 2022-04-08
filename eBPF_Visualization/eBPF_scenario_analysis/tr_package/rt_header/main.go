//go:build linux
// +build linux

// This program demonstrates attaching an eBPF program to a kernel symbol.
// The eBPF program will be attached to the start of the sys_execve
// kernel function and prints out the number of times it has been called
// every second.
package main

import (
	"bytes"
	"encoding/binary"
	"flag"
	_ "flag"
	"fmt"
	"log"
	"time"
	_ "time"

	"github.com/cilium/ebpf/link"
	_ "github.com/cilium/ebpf/perf"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"golang.org/x/sys/unix"
)

// $BPF_CLANG and $BPF_CFLAGS are set by the Makefile.
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc $BPF_CLANG -cflags $BPF_CFLAGS --target=amd64 bpf rx_package.c -- -I../headers
const mapKey uint32 = 0

type skb_message struct {
	Time              uint64
	Len              uint32
	Data_len         uint32
	Transport_header uint16
	Network_header   uint16
	Mac_header       uint16
	Name			 [30]byte
}

func main() {
	var pid uint
	flag.UintVar(&pid,"pid",0,"pid")
	flag.Parse()
	fn := "ip_local_out"
	fn1 := "__tcp_transmit_skb"
	fn2 := "__ip_queue_xmit"
	fn3 := "__dev_queue_xmit"
	fn4 := "eth_type_trans"
	fn5 := "ip_rcv"
	fn6 := "ip_local_deliver_finish"
	fn7 := "ip_protocol_deliver_rcu"
	fn8 := "tcp_rcv_established"
	fn9 := "tcp_data_queue"
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}
	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatalf("loading objects: %v", err)
	}
	defer objs.Close()
	kp1, err1 := link.Kprobe(fn1, objs.KprobeTcpTransmitSkb)
	if err1 != nil {
		log.Fatalf("opening kprobe: %s", err1)
	}
	defer kp1.Close()
	kp2, err2 := link.Kprobe(fn2, objs.KprobeIpQueueXmit)
	if err2 != nil {
		log.Fatalf("opening kprobe: %s", err2)
	}
	defer kp2.Close()

	kp3, err3 := link.Kprobe(fn, objs.KprobeIpLocalOut)
	if err3 != nil {
		log.Fatalf("opening kprobe: %s", err3)
	}
	defer kp3.Close()
	kp4, err4 := link.Kprobe(fn3, objs.KprobeDevQueueXmit)
	if err4 != nil {
		log.Fatalf("opening kprobe: %s", err4)
	}
	defer kp4.Close()
	kp5, err5 := link.Kprobe(fn4, objs.KprobeEthTypeTrans)
	if err5 != nil {
		log.Fatalf("opening kprobe: %s", err5)
	}
	defer kp5.Close()
	kp6, err6 := link.Kprobe(fn5, objs.KprobeIpRcv)
	if err6 != nil {
		log.Fatalf("opening kprobe: %s", err6)
	}
	defer kp6.Close()
	kp7, err7 := link.Kprobe(fn6, objs.KprobeIpLocalDeliverFinish)
	if err7 != nil {
		log.Fatalf("opening kprobe: %s", err7)
	}
	defer kp7.Close()
	kp8, err8 := link.Kprobe(fn7, objs.KprobeIpProtocolDeliverRcu)
	if err8 != nil {
		log.Fatalf("opening kprobe: %s", err8)
	}
	defer kp8.Close()
	kp9, err9 := link.Kprobe(fn8, objs.KprobeTcpRcvEstablished)
	if err9 != nil {
		log.Fatalf("opening kprobe: %s", err9)
	}
	defer kp9.Close()
	kp, err := link.Kprobe(fn9, objs.KprobeTcpDataQueue)
	if err != nil {
		log.Fatalf("opening kprobe: %s", err)
	}
	defer kp.Close()

	if pid != 0 {
		objs.PidforUser.Update(mapKey,uint32(pid),0)
	}
	ticker := time.NewTicker(1 * time.Second)
	log.Println("Waiting for events..")
	rd, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		panic(err)
	}
	defer rd.Close()

	var event skb_message
	for range ticker.C {
		record, err := rd.Read()
		if err != nil {
			panic(err)
		}
		// Data is padded with 0 for alignment
		//fmt.Println("Sample:", record.RawSample)
		err1 := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &event)
		if err1 != nil {
			fmt.Printf("failed to decode received data: %s\n", err)
			continue
		}
		
		fmt.Printf("%15s\t%15s\t%5d\t%5d\t%5d\t%5d\t%5d\n",time.Unix(int64(event.Time),0).Format("2006-01-02 15:04:05"),unix.ByteSliceToString(event.Name[:]),event.Mac_header, event.Network_header, event.Transport_header, event.Len, event.Data_len)
	}
}