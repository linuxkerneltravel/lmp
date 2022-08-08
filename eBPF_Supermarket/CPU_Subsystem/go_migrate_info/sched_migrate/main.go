//go:build linux
// +build linux

// This program demonstrates attaching an eBPF program to a kernel tracepoint.
// The eBPF program will be attached to the page allocation tracepoint and
// prints out the number of times it has been reached. The tracepoint fields
// are printed into /sys/kernel/debug/tracing/trace_pipe.
package main

import (
	"log"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

// $BPF_CLANG and $BPF_CFLAGS are set by the Makefile.
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc $BPF_CLANG -cflags $BPF_CFLAGS bpf tracepoint.c -- -I../headers -I../..

const mapKey uint32 = 0

type migrate_value struct {
	time     uint64
	pid      int
	prio     int
	orig_cpu int
	dest_cpu int
}

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
	kp, err := link.Tracepoint("sched", "sched_migrate_task", objs.SchedSwitch, nil)
	if err != nil {
		log.Fatalf("opening tracepoint: %s", err)
	}
	defer kp.Close()

	// Read loop reporting the total amount of times the kernel
	// function was entered, once per second.
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	// objs.KprobeMap.Pin("/sys/fs/bpf/migrate");
	log.Println("Waiting for events..")

	var pos uint64 = 1
	for range ticker.C {
		var key uint32 = 0
		var value uint64
		var delList []uint32

		objs.KprobeMap.Lookup(&key, &value)
		log.Printf("--------total migration: %v-------\n", value)

		for i := pos; i <= value; i++ {
			var info [6]int32
			var time uint64
			// var val migrate_value
			key = uint32(i)

			err := objs.Queue.Lookup(key, &info)
			objs.Queue.Lookup(key, &time)
			if err != nil {
				log.Printf("Failed to read key(%v) %v\n", key, err)
				return
			}
			// 输出migrate的时间戳
			log.Printf("timestamp(%v) #%v: pid %v, prio %v, core%v -> core%v\n",
				time, key, info[2], info[3], info[4], info[5])

			delList = append(delList, key)
		}
		pos = value + 1

		for _, key := range delList {
			objs.Queue.Delete(key)
		}
	}
}
