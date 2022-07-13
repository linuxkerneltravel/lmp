package main

import (
	"bytes"
	"encoding/binary"
	"flag"
	"fmt"
	"os"
	"os/signal"

	"github.com/iovisor/gobpf/bcc"
)

const headerFieldStrSize = 128

type headerField struct {
	Size uint32
	Msg  [headerFieldStrSize]byte
}

// http2HeaderEvent's memory layout is identical to the go_grpc_http2_header_event_t in bpf_program.go, such that the
// event data obtained from the perf buffer can be directly copied to http2HeaderEvent.
type http2HeaderEvent struct {
	Name  headerField
	Value headerField
}

func formatHeaderField(field headerField) string {
	return string(field.Msg[0:field.Size])
}

func formatHeaderEvent(event http2HeaderEvent) string {
	return fmt.Sprintf("[name='%s' value='%s']", formatHeaderField(event.Name), formatHeaderField(event.Value))
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

var (
	binaryProg string
	symbol     string
	probeFn    string
)

func init() {
	flag.StringVar(&binaryProg, "binary", "", "The binary to probe")
}

func main() {
	flag.Parse()
	if len(binaryProg) == 0 {
		panic("Argument --binary needs to be specified")
	}

	bccMod := bcc.NewModule(bpfProgram, []string{})
	const loopWriterWriteHeaderSymbol = "google.golang.org/grpc/internal/transport.(*loopyWriter).writeHeader"
	const loopWriterWriteHeaderProbeFn = "probe_loopy_writer_write_header"
	mustAttachUprobe(bccMod, binaryProg, loopWriterWriteHeaderSymbol, loopWriterWriteHeaderProbeFn)

	const http2ServerOperateHeadersSymbol = "google.golang.org/grpc/internal/transport.(*http2Server).operateHeaders"
	const http2ServerOperateHeadersProbeFn = "probe_http2_server_operate_headers"
	mustAttachUprobe(bccMod, binaryProg, http2ServerOperateHeadersSymbol, http2ServerOperateHeadersProbeFn)
	fmt.Println("begin...")
	defer func() {
		bccMod.Close()
	}()

	table := bcc.NewTable(bccMod.TableId("go_http2_header_events"), bccMod)
	ch := make(chan []byte)

	pm, err := bcc.InitPerfMap(table, ch, nil)
	if err != nil {
		panic(err)
	}

	// Watch Ctrl-C so we can quit this program.
	intCh := make(chan os.Signal, 1)
	signal.Notify(intCh, os.Interrupt)

	pm.Start()
	defer pm.Stop()

	for {
		select {
		case <-intCh:
			fmt.Println("Terminating")
			os.Exit(0)
		case v := <-ch:
			var parsed http2HeaderEvent
			if err := binary.Read(bytes.NewBuffer(v), bcc.GetHostByteOrder(), &parsed); err != nil {
				panic(err)
			}
			fmt.Println(formatHeaderEvent(parsed))
		}
	}
}
