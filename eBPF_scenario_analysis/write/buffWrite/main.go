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
	_ "encoding/json"
	"flag"
	"fmt"
	"log"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	"github.com/cilium/ebpf/rlimit"
	"golang.org/x/sys/unix"
)

// $BPF_CLANG and $BPF_CFLAGS are set by the Makefile.
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc $BPF_CLANG -cflags $BPF_CFLAGS --target=amd64 bpf kprobe.c -- -I../headers

const mapKey uint32 = 0

type buffWriteEvent struct {
	Pid      uint32
	Offset   uint64
	Bytes    uint64
	Index    uint64
	Pos      uint64
	Filename [20]byte
	Ts       uint64
}

func main() {

	var mypid int64
	pid := flag.Int("pid", -1, "attach to pid, default is all processes")
	flag.Parse()
	if *pid != -1 {
		mypid = int64(*pid)
	}

	// Name of the kernel function to trace.
	fn := "ext4_da_write_begin"

	// Allow the current process to lock memory for eBPF resources.
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}

	// Load pre-compiled programs and maps into the kernel.
	objs := bpfObjects{}
	spec, err := loadBpf()
	if err != nil {
		log.Fatalf("loading objects: %s", err)
		return
	}
	consts := map[string]interface{}{
		"my_pid": mypid,
	}

	if err := spec.RewriteConstants(consts); err != nil {
		fmt.Errorf("error RewriteConstants: %w", err)
	}
	if err := spec.LoadAndAssign(&objs, nil); err != nil {
		log.Fatalf("loading objects: %s", err)
	}
	defer objs.Close()
	// Open a Kprobe at the entry point of the kernel function and attach the
	// pre-compiled program. Each time the kernel function enters, the program
	// will increment the execution counter by 1. The read loop below polls this
	// map value once per second.
	kp, err := link.Kprobe(fn, objs.KprobeProg)
	if err != nil {
		log.Fatalf("opening kprobe: %s", err)
	}
	defer kp.Close()

	// Read loop reporting the total amount of times the kernel
	// function was entered, once per second.
	ticker := time.NewTicker(1 * time.Second)

	log.Println("Waiting for events..")

	rd, err := perf.NewReader(objs.KprobeMap, 4096)
	if err != nil {
		panic(err)
	}
	defer rd.Close()
	fmt.Printf("%10s\t%20s\t%10s\t%5s\t%5s\t%10s\t%10s\n", "PID", "FileName", "FilePos", "PageIndex", "PageOffset", "Bytes", "Time")
	for range ticker.C {
		var event buffWriteEvent
		record, err := rd.Read()
		if err != nil {
			panic(err)
		}

		// Data is padded with 0 for alignment
		err1 := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &event)
		if err1 != nil {
			fmt.Printf("failed to decode received data: %s\n", err)
			continue
		}
		fmt.Printf("%10d\t%20s\t%10d\t%10d\t%10d\t%10d\t%10d\n", event.Pid, unix.ByteSliceToString(event.Filename[:]), event.Pos, event.Index, event.Offset, event.Bytes, event.Ts)
	}
}
