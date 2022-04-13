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
	"fmt"
	"log"
	_"time"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	"github.com/cilium/ebpf/rlimit"
	_ "golang.org/x/sys/unix"
)

// $BPF_CLANG and $BPF_CFLAGS are set by the Makefile.
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc $BPF_CLANG -cflags $BPF_CFLAGS --target=amd64 bpf ext4.c -- -I../headers

const mapKey uint32 = 0
type ext4WriteEvent struct {
	Pid       uint32
	Type      uint32
	IovOffset uint32
	Count     uint32
	Pos       uint64
	Flags     uint64
	Hint      uint32
	Ioprio    uint32
	Cookie    uint32
}

func main() {
	var pid uint
	flag.UintVar(&pid,"pid",0,"pid")
	flag.Parse()
	fn := "ext4_file_write_iter"
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}
	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatalf("loading objects: %v", err)
	}
	defer objs.Close()
	kp, err := link.Kprobe(fn, objs.KprobeExt4FileWriteIter)
	if err != nil {
		log.Fatalf("opening kprobe: %s", err)
	}
	defer kp.Close()

	if pid != 0 {
		objs.PidforUser.Update(mapKey,uint32(pid),0)
	}
	//ticker := time.NewTicker(1 * time.Second)

	log.Println("Waiting for events..")

	rd, err := perf.NewReader(objs.bpfMaps.Events, 4096)
	if err != nil {
		panic(err)
	}
	defer rd.Close()
	for {
		event := ext4WriteEvent{

		}
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
		fmt.Printf("%10d\t%20d\t%5d\t%5d\t%5d\t%10d\n", event.Pid, event.Type, event.IovOffset, event.Count, event.Pos, event.Flags)
	}
}
