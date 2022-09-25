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
	"runtime"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

// $BPF_CLANG and $BPF_CFLAGS are set by the Makefile.
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc $BPF_CLANG -cflags $BPF_CFLAGS bpf tracepoint.c -- -I../headers -I../..

const mapKey uint32 = 0

func find_largest_cnt(migrateMap map[int]int) (int, int) {
	maxPid := -1
	maxCnt := 0
	for key, val := range migrateMap {
		if val > maxCnt {
			maxPid = key
			maxCnt = val
		}
	}
	return maxPid, maxCnt
}

type MigrateInfo struct{
	freq int
	mostPid int
	maxCnt int
}

func updateMigrateInfo(objs bpfObjects, pos uint64) (MigrateInfo, uint64, bool) {
	// pos是上一秒结束时的数目+1，即为本秒的第一个位置
	var key uint32 = 0
	var value uint64
	var delList []uint32

	// value是当前migrate的数目
	objs.MigrateCount.Lookup(&key, &value)

	var migrateMap map[int]int = make(map[int]int)
	for i := pos; i <= value; i++ {
		var info [6]int32 // 用数组的形式获取结构体
		// var time uint64
		key = uint32(i)

		err := objs.Queue.Lookup(key, &info)
		// objs.Queue.Lookup(key, &time)
		if err != nil {
			log.Printf("Failed to read key(%v) %v\n", key, err)
			return MigrateInfo{}, 0, false
		}
		
		pid := int(info[2])
		cnt := migrateMap[pid]
		if cnt == 0 {
			migrateMap[pid] = 1
		} else {
			migrateMap[pid] += 1
		}

		delList = append(delList, key)
	}
	deltaMigrate := value - pos + 1
	maxPid, maxCnt := find_largest_cnt(migrateMap)

	pos = value + 1

	// 删掉已经读取到的内容
	for _, key := range delList {
		objs.Queue.Delete(key)
	}

	migrateInfo := MigrateInfo{}
	migrateInfo.freq = int(deltaMigrate)
	migrateInfo.mostPid = maxPid
	migrateInfo.maxCnt = maxCnt
	return migrateInfo, pos, true
}

func Min(x, y int) int {
	if x < y {
		return x
	}
	return y
}

func printTableHead(cnt_cpu int) {
	timeStr := time.Now().Format("15:04:05")
	runqlen_str := ""

	for i := 0; i < Min(4, cnt_cpu); i++ {
		str := fmt.Sprintf("rqlen[%d]", i)
		runqlen_str = runqlen_str + str + "  "
	}
	if cnt_cpu > 4 {
		runqlen_str = runqlen_str + "[other]  "
	}
	fmt.Printf("%s proc/s  cswch/s  %sunintr  irqTime/us  softirq/us  idle/ms  migrate: freq  max_Pid  maxCnt\n",
		timeStr, runqlen_str)
}

func getRunqlenEntry(rqlens []uint64, cnt_cpu int) string {
	for i := 0; i < cnt_cpu; i++ {
		if rqlens[i] > 0 {
			rqlens[i] -= 1
		}
	}
	runqlen_str := ""

	for i := 0; i < Min(4, cnt_cpu); i++ {
		str := fmt.Sprintf("%8d", rqlens[i])
		runqlen_str = runqlen_str + str + "  "
	}
	if cnt_cpu > 4 {
		other := 0
		for i := 4; i < cnt_cpu; i++ {
			other += int(rqlens[i])
		}
		str := fmt.Sprintf("%7d", other)
		runqlen_str = runqlen_str + str + "  "
	}
	return runqlen_str
}

func main() {
	cnt_cpu := runtime.NumCPU() // 获取cpu个数

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
	kp8, _ := link.Tracepoint("sched", "sched_migrate_task", objs.SchedMigrateTask, nil)
	defer kp1.Close()
	defer kp2.Close()
	defer kp3.Close()
	defer kp4.Close()
	defer kp5.Close()
	defer kp6.Close()
	defer kp7.Close()
	defer kp8.Close()

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
	var pos uint64 = 1

	printTableHead(cnt_cpu)
	for range ticker.C {
		var key uint32
		var proc_s, cswch_s uint64
		var unintr int64
		var runqlen_percpu []uint64
		var unintr_percpu []int64

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
		objs.Runqlen.Lookup(key, &runqlen_percpu)
		// 将全部的runqlen相加
		// runqlen = 0
		// for cpuid := 0; cpuid < len(runqlen_percpu); cpuid++ {
		// 	runqlen += runqlen_percpu[cpuid]
		// }

		key = 0
		objs.NrUnintr.Lookup(key, &unintr_percpu)
		unintr = 0
		for cpuid := 0; cpuid < len(unintr_percpu); cpuid++ {
			unintr += unintr_percpu[cpuid]
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

		migrateInfo, _pos, _ := updateMigrateInfo(objs, pos)
		pos = _pos

		timeStr := time.Now().Format("15:04:05")
		runqlen_str := getRunqlenEntry(runqlen_percpu, cnt_cpu)
		fmt.Printf("%s %6d  %7d  %s%6d  %10d  %10d  %7d  %13d  %7d  %6d\n",
			timeStr, proc_s, cswch_s, runqlen_str, unintr,
			dtaIrq, dtaSoft, dtaIdle/1000000,
			migrateInfo.freq, migrateInfo.mostPid, migrateInfo.maxCnt,
		)

		actualTime += 1
		if actualTime%12 == 0 {
			fmt.Println()
			printTableHead(cnt_cpu)
		}

		if actualTime == 5 {
			break
		}
	}
}
