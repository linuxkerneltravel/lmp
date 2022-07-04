//go:build linux
// +build linux

package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

// $BPF_CLANG and $BPF_CFLAGS are set by the Makefile.
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc $BPF_CLANG -cflags $BPF_CFLAGS --target=amd64 bpf interrupt.c -- -I../headers
type intr_message struct {
    Vector    uint64
	Pid	      uint32
	Stack_id  uint32
}

func main() {

	fn := "do_error_trap"

	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}
	
	
	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatalf("loading objects: %v", err)
	}
	defer objs.Close()

	kp, err := link.Kprobe(fn, objs.KprobeDoErrorTrap,nil)
	if err != nil {
		log.Fatalf("opening kprobe: %s", err)
	}
	defer kp.Close()

	ticker := time.NewTicker(1 * time.Second)
	log.Println("Waiting for events..")
	rd, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		panic(err)
	}
	defer rd.Close()
	event := intr_message{}
	for range ticker.C {
		var ip [127]uint64 =[127]uint64{0};
		record, err := rd.Read()
		if err != nil {
			panic(err)
		}
		err1 := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &event)
		if err1 != nil {
			fmt.Printf("failed to decode received data: %s\n", err)
			continue
		}
		err2 := objs.bpfMaps.StackTraces.Lookup(event.Stack_id,&ip)
		if err2!=nil{
			panic(err2)
		}
		
		m,err := NewKernelSymbolsMap()
		if err != nil {
		 	fmt.Fprintln(os.Stderr, err)
		 	os.Exit(-1)
		}
		fmt.Printf("%v   %v     %v\n",event.Pid,event.Vector,event.Stack_id)
		for i:=0;i<127;i++ {
			if ip[i] == 0{
				continue
			}
			sym, err := m.GetSymbolByAddr(ip[i])
			
			if err != nil {
				fmt.Fprintln(os.Stderr, err)
				continue
			}
		
			if sym.Address == 0 || sym.Name == "" {
				fmt.Fprintln(os.Stderr, "could not find symbol to attach to")
				os.Exit(-1)
			}
			fmt.Printf("%v\n",sym.Name)
		}
	}
	return
}

