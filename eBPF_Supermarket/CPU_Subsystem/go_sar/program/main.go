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
	kp1, _ := link.Tracepoint("sched", "sched_switch", objs.SchedSwitch, nil)
	kp2, _ := link.Tracepoint("sched", "sched_process_fork", objs.SchedProcessFork, nil)
	kp3, _ := link.Kprobe("update_rq_clock", objs.UpdateRqClock, nil)
	kp4, _ := link.Tracepoint("irq", "irq_handler_entry", objs.IrqHandlerEntry, nil)
	kp5, _ := link.Tracepoint("irq", "irq_handler_exit", objs.IrqHandlerExit, nil)
	kp6, _ := link.Tracepoint("irq", "softirq_entry", objs.SoftirqEntry, nil)
	kp7, _ := link.Tracepoint("irq", "softirq_exit", objs.SoftirqExit, nil)
	defer kp1.Close()
	defer kp2.Close()
	defer kp3.Close()
	defer kp4.Close()
	defer kp5.Close()
	defer kp6.Close()
	defer kp7.Close()

	// Read loop reporting the total amount of times the kernel
	// function was entered, once per second.
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	var proc uint64 = 0
	var cswch uint64 = 0
	var irqTime uint64 = 0
	var softTime uint64 = 0
	var idleTime uint64 = 0
	var actualTime uint64 = 0

	timeStr := time.Now().Format("15:04:05")
	fmt.Printf("%s proc/s  cswch/s  runqlen  irqTime/us  softirq/us  idle/ms\n", timeStr)
	for range ticker.C {
		var key uint32
		var proc_s, cswch_s, runqlen uint64
		var all_cpu_value []uint64

		// 上下文切换数
		key = 0
		objs.CountMap.Lookup(key, &cswch_s)
		cswch_s, cswch = cswch_s-cswch, cswch_s

		// 每秒新建进程数
		key = 1
		err := objs.CountMap.Lookup(key, &proc_s)
		if err != nil {
			log.Fatalf("Read Map err, %v\n", err)
		}
		proc_s, proc = proc_s-proc, proc_s

		// 计算队列长度
		key = 0
		objs.Runqlen.Lookup(key, &all_cpu_value)
		runqlen = 0
		for cpuid := 0; cpuid < 128; cpuid++ {
			runqlen += all_cpu_value[cpuid]
		}

		// irq所占的时间ns
		key = 0
		_irqTime := irqTime
		objs.IrqLastTime.Lookup(key, &irqTime)
		dtaIrq := (irqTime - _irqTime) / 1000 // 每秒的irq时间/us(两个CPU)

		key = 0
		_softTime := softTime
		objs.SoftirqLastTime.Lookup(key, &softTime)
		dtaSoft := (softTime - _softTime) / 1000

		key = 0
		_idleTime := idleTime
		objs.ProcLastTime.Lookup(key, &idleTime)
		dtaIdle := idleTime - _idleTime

		timeStr := time.Now().Format("15:04:05")
		fmt.Printf("%s %6d  %7d  %7d  %10d  %10d  %7d\n", timeStr, proc_s, cswch_s, runqlen,
			dtaIrq, dtaSoft, dtaIdle/1000000)

		actualTime += 1
	}
}
