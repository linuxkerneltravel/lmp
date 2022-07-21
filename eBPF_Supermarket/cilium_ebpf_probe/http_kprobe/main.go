package http_kprobe

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"flag"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"unsafe"

	"github.com/fatih/color"
	"github.com/iovisor/gobpf/bcc"
)

var (
	tracePID     int
	printEnabled bool
	podname      string
)

//func init() {
//	flag.IntVar(&tracePID, "pid", -1, "The pid to trace")
//	flag.BoolVar(&printEnabled, "print", true, "Print output")
//}

type EventType int32

const (
	ETSyscallAddr EventType = iota + 1
	ETSyscallWrite
	ETSyscallClose
)

type Attributes struct {
	EvType  EventType
	Fd      int32
	Bytes   int32
	MsgSize int32
}

type SyscallWriteEvent struct {
	Attr Attributes
	Msg  []byte
}

type MessageInfo struct {
	SocketInfo []byte
	Buf        bytes.Buffer
}

func mustAttachKprobeToSyscall(m *bcc.Module, probeType int, syscallName string, probeName string) {
	fnName := bcc.GetSyscallFnName(syscallName)
	kprobe, err := m.LoadKprobe(probeName)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to attach probe: %s\n", err)
		os.Exit(1)
	}

	if probeType == bcc.BPF_PROBE_ENTRY {
		err = m.AttachKprobe(fnName, kprobe, -1)
	} else {
		err = m.AttachKretprobe(fnName, kprobe, -1)
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to attach entry probe %s: %s\n", probeName, err)
		os.Exit(1)
	}
}

type requestHandler struct {
	FdMap map[int32]*MessageInfo
}

func (r *requestHandler) HandleBPFEvent(v []byte) {
	var ev SyscallWriteEvent
	if err := binary.Read(bytes.NewBuffer(v), bcc.GetHostByteOrder(), &ev.Attr); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to decode struct: %+v\n", err)
		return
	}
	ev.Msg = make([]byte, ev.Attr.MsgSize)
	if err := binary.Read(bytes.NewBuffer(v[unsafe.Sizeof(ev.Attr):]), bcc.GetHostByteOrder(), &ev.Msg); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to decode struct: %+v\n", err)
		return
	}

	switch ev.Attr.EvType {
	case ETSyscallAddr:
		r.FdMap[ev.Attr.Fd] = &MessageInfo{
			SocketInfo: ev.Msg,
		}
	case ETSyscallWrite:
		if elem, ok := r.FdMap[ev.Attr.Fd]; ok {
			elem.Buf.Write(ev.Msg)
		}
	case ETSyscallClose:
		if msgInfo, ok := r.FdMap[ev.Attr.Fd]; ok {
			delete(r.FdMap, ev.Attr.Fd)

			go parseAndPrintMessage(msgInfo)
		} else {
			fmt.Fprintf(os.Stderr, "Missing request with FD: %d\n", ev.Attr.Fd)
			return
		}
	}
}

func parseAndPrintMessage(msgInfo *MessageInfo) {

	resp, err := http.ReadResponse(bufio.NewReader(&msgInfo.Buf), nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to parse request\n")
		return
	}

	body := resp.Body
	b, _ := ioutil.ReadAll(body)
	body.Close()
	fmt.Println("\ndata from ", podname)
	fmt.Printf("StatusCode: %s, Len: %s, ContentType: %s, Body: %s\n",
		color.GreenString("%d", resp.StatusCode),
		color.GreenString("%d", resp.ContentLength),
		color.GreenString("%s", resp.Header["Content-Type"]),
		color.GreenString("%s", string(b)))

}

func GetHttpViaKprobe(tracePID int, p string) {
	flag.Parse()
	podname = p
	if tracePID < 0 {
		panic("Argument --pid needs to be specified")
	}
	bpfProgramResolved := strings.ReplaceAll(bpfProgram, "$PID", fmt.Sprintf("%d", tracePID))
	bccMod := bcc.NewModule(bpfProgramResolved, []string{})
	mustAttachKprobeToSyscall(bccMod, bcc.BPF_PROBE_ENTRY, "accept4", "syscall__probe_entry_accept4")
	mustAttachKprobeToSyscall(bccMod, bcc.BPF_PROBE_RETURN, "accept4", "syscall__probe_ret_accept4")
	mustAttachKprobeToSyscall(bccMod, bcc.BPF_PROBE_ENTRY, "write", "syscall__probe_write")
	mustAttachKprobeToSyscall(bccMod, bcc.BPF_PROBE_ENTRY, "close", "syscall__probe_close")

	table := bcc.NewTable(bccMod.TableId("syscall_write_events"), bccMod)
	ch := make(chan []byte)

	pm, err := bcc.InitPerfMap(table, ch, nil)
	if err != nil {
		panic(err)
	}

	intCh := make(chan os.Signal, 1)
	signal.Notify(intCh, os.Interrupt)

	pm.Start()
	defer pm.Stop()

	requestHander := &requestHandler{
		FdMap: make(map[int32]*MessageInfo, 0),
	}
	fmt.Println("kprobe for http begins...")
	for {
		select {
		case <-intCh:
			fmt.Println("Terminating")
			os.Exit(0)
		case v := <-ch:
			requestHander.HandleBPFEvent(v)
		}
	}
}
