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
	"encoding/json"
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

type ksysWriteEvent struct {
	Pid   uint32
	Count uint32
	Fd    uint32
	Ts    uint64
	Buf   [20]byte
}
type ksysWriteObj struct {
	Pid     uint32
	Count   uint32
	Fd      uint32
	Time    uint64
	Content string
}

type JsonResult struct {
	FuncName string
	Arg      ksysWriteObj
}

func main() {

	var mypid int64
	pid := flag.Int("pid", -1, "attach to pid, default is all processes")
	flag.Parse()
	if *pid != -1 {
		mypid = int64(*pid)
	} else {
		mypid = 0
	}

	// Name of the kernel function to trace.
	fn := "ksys_write"

	// Allow the current process to lock memory for eBPF resources.
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}

	// Load pre-compiled programs and maps into the kernel.
	// objs := bpfObjects{}
	// if err := loadBpfObjects(&objs, nil); err != nil {
	// 	log.Fatalf("loading objects: %v", err)
	// }
	// defer objs.Close()

	// Load pre-compiled programs and maps into the kernel.
	objs := bpfObjects{}
	spec, err := loadBpf()
	if err != nil {
		log.Fatalf("loading objects: %s", err)
		return
	}
	funcName := "kprobe_execve"
	// 过滤pid
	for i, ins := range spec.Programs[funcName].Instructions {
		if ins.Reference == "MY_PID" {
			spec.Programs[funcName].Instructions[i].Constant = mypid
			spec.Programs[funcName].Instructions[i].Offset = 0
			fmt.Printf("found the my_const and replaced, index: %d, opCode: %d\n", i, ins.OpCode)
		}
	}
	if err := spec.LoadAndAssign(&objs, nil); err != nil {
		log.Fatalf("loading objects: %s", err)
	}
	defer objs.Close()
	// Open a Kprobe at the entry point of the kernel function and attach the
	// pre-compiled program. Each time the kernel function enters, the program
	// will increment the execution counter by 1. The read loop below polls this
	// map value once per second.
	kp, err := link.Kprobe(fn, objs.KprobeExecve)
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
	// fmt.Printf("%10s\t%20s\t%5s\t%5s\t%5s\n", "PID", "FileName", "Fd", "COUNT", "Time")
	for range ticker.C {
		var event ksysWriteEvent
		record, err := rd.Read()
		if err != nil {
			panic(err)
		}

		// Data is padded with 0 for alignment
		// fmt.Println("Sample:", record.RawSample)
		err1 := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &event)
		if err1 != nil {
			fmt.Printf("failed to decode received data: %s\n", err)
			continue
		}
		// fmt.Printf("%10d\t%20s\t%5d\t%5d\t%10d\n", event.Pid, unix.ByteSliceToString(event.Buf[:]), event.Fd, event.Count, event.Ts)
		obj := ksysWriteObj{
			Pid:     event.Pid,
			Content: unix.ByteSliceToString(event.Buf[:]),
			Count:   event.Count,
			Fd:      event.Fd,
			Time:    event.Ts,
		}
		jsonObj := JsonResult{
			FuncName: fn,
			Arg:      obj,
		}
		jsonStr, err := json.Marshal(jsonObj)
		if err != nil {
			fmt.Println("error:", err)
		}
		fmt.Println(string(jsonStr))
		// var value uint64
		// if err := objs.KprobeMap.Lookup(mapKey, &value); err != nil {
		// 	log.Fatalf("reading map: %v", err)
		// }
		// log.Printf("%s called %d times\n", fn, value)
	}
}
