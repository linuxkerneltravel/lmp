//go:build linux
// +build linux

// This program demonstrates attaching an eBPF program to a kernel tracepoint.
// The eBPF program will be attached to the page allocation tracepoint and
// prints out the number of times it has been reached. The tracepoint fields
// are printed into /sys/kernel/debug/tracing/trace_pipe.
package main

import (
	"fmt"
	"log"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

// $BPF_CLANG and $BPF_CFLAGS are set by the Makefile.
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc $BPF_CLANG -cflags $BPF_CFLAGS bpf tracepoint.c -- -I../headers -I../..

const mapKey uint32 = 0

func main() {
	// Allow the current process to lock memory for eBPF resources.
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}

	// Load pre-compiled programs and maps into the kernel.
	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatalf("loading objects: %v", err)
	}
	defer objs.Close()

	// Open a tracepoint and attach the pre-compiled program. Each time
	// the kernel function enters, the program will increment the execution
	// counter by 1. The read loop below polls this map value once per
	// second.
	// The first two arguments are taken from the following pathname:
	// /sys/kernel/debug/tracing/events/kmem/mm_page_alloc
	kp1, err := link.Tracepoint("sched", "sched_switch", objs.SchedSwitch, nil)
	kp2, err := link.Tracepoint("sched", "sched_process_fork", objs.SchedProcessFork, nil)
	kp3, err := link.Kprobe("update_rq_clock", objs.UpdateRqClock, nil)
	if err != nil {
		log.Fatalf("opening tracepoint: %s", err)
	}
	defer kp1.Close()
	defer kp2.Close()
	defer kp3.Close()

	// Read loop reporting the total amount of times the kernel
	// function was entered, once per second.
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	var proc uint64 = 0
	var cswch uint64 = 0

	timeStr := time.Now().Format("15:04:05")
	fmt.Printf("%s proc/s  cswch/s  runqlen\n", timeStr)
	for range ticker.C {
		var key uint32
		var proc_s, cswch_s, runqlen uint64
		var all_cpu_value []uint64

		key = 0
		objs.CountMap.Lookup(key, &cswch_s)
		cswch_s, cswch = cswch_s-cswch, cswch_s

		key = 1
		err := objs.CountMap.Lookup(key, &proc_s)
		if err != nil {
			log.Fatalf("Read Map err, %v\n", err)
		}
		proc_s, proc = proc_s-proc, proc_s

		key = 0
		objs.Runqlen.Lookup(key, &all_cpu_value)

		runqlen = 0
		for cpuid := 0; cpuid < 128; cpuid++ {
			runqlen += all_cpu_value[cpuid]
		}

		timeStr := time.Now().Format("15:04:05")
		fmt.Printf("%s %6d  %7d  %7d\n", timeStr, proc_s, cswch_s, runqlen)
	}
}
