package main

import (
	"encoding/binary"
	"flag"
	"fmt"
	"github.com/iovisor/gobpf/bcc"
)

const bpfProgram = `
#include <uapi/linux/ptrace.h>
BPF_PERF_OUTPUT(trace);
inline int probehello(struct pt_regs *ctx) {
  long val = PT_REGS_PARM1(ctx);
  trace.perf_submit(ctx, &val, sizeof(val));
  return 0;
}
`

var binaryProg string

func init() {
	flag.StringVar(&binaryProg, "binary", "/root/go/src/lmp/eBPF_Supermarket/cilium_ebpf_probe/cuprobe/test", "The binary to probe")
}
func mustAttachUprobe(bccMod *bcc.Module, binaryProg, symbol, probeFn string) {
	uprobeFD, err := bccMod.LoadUprobe(probeFn)
	if err != nil {
		panic(err)
	}
	err = bccMod.AttachUprobe(binaryProg, symbol, uprobeFD, -1 /*pid*/)
	if err != nil {
		panic(err)
	}
}
func main() {
	flag.Parse()
	bccMod := bcc.NewModule(bpfProgram, []string{})
	const probeSymbol = "hello"
	const probeFunc = "probehello"
	mustAttachUprobe(bccMod, binaryProg, probeSymbol, probeFunc)

	fmt.Println("uprobe for C begin...")
	defer func() {
		bccMod.Close()
	}()

	table := bcc.NewTable(bccMod.TableId("trace"), bccMod)
	ch := make(chan []byte)

	pm, err := bcc.InitPerfMap(table, ch, nil)
	if err != nil {
		panic(err)
	}

	pm.Start()
	defer pm.Stop()

	for {
		select {
		case v := <-ch:
			d := binary.LittleEndian.Uint64(v)
			fmt.Printf("Value = %v\n", d)
		}
	}
}
