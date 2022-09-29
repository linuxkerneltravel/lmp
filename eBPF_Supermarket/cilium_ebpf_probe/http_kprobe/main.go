package http_kprobe

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"flag"
	"fmt"
	"github.com/xuri/excelize/v2"
	"io/ioutil"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"time"
	"unsafe"

	"github.com/fatih/color"
	"github.com/iovisor/gobpf/bcc"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/push"
)

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
	StartNs int64
	EndNs   int64
}

type SyscallWriteEvent struct {
	Attr Attributes
	Msg  []byte
}

type MessageInfo struct {
	GoTime     int64
	Time_ns    int64
	SocketInfo []byte
	Buf        bytes.Buffer
}

var (
	tracePID            int
	printEnabled        bool
	podname             string
	count               int
	prome               bool
	histogramRegistered = prometheus.NewHistogram(
		prometheus.HistogramOpts{
			Name:    "http_spend",
			Help:    "A histogram of normally distributed http spend time(us).",
			Buckets: prometheus.LinearBuckets(0, 800, 20),
		},
	)
	statusMap map[int]prometheus.Gauge
	f         = excelize.NewFile()
	exceli    int
)

//为Map上锁
type SpendTimeMap struct {
	sync.RWMutex
	SpendTime map[time.Time][]int64
}
type RequestMap struct {
	sync.RWMutex
	Request map[time.Time][]*http.Response
}

func Histogram_Push(podname string, spendtime int64, gotime int64) {
	histogramRegistered.Observe(float64(spendtime / 1000 / 1000))
	if err := push.New("http://10.10.103.122:9091", "HTTPSpend"). // push.New("pushgateway地址", "job名称")
									Collector(histogramRegistered).                                 //gotime.Format("2006-01-02 15:04:05")                                                                                                  // Collector(completionTime) 给指标赋值
									Grouping("podname", podname).Grouping("instance", "spendtime"). // 给指标添加标签，可以添加多个
									Push(); err != nil {
		fmt.Println("Could not push completion time to Pushgateway:", err)
	}

}

func Gauge_Push(podname string, statuscode int, gotime int64) {
	statusMap[statuscode].Add(1)
	if err := push.New("http://10.10.103.122:9091", "HTTPStatus"). // push.New("pushgateway地址", "job名称")
									Collector(statusMap[statuscode]).                                                                                 //gotime.Format("2006-01-02 15:04:05")                                                                                                  // Collector(completionTime) 给指标赋值
									Grouping("podname", podname).Grouping("instance", "statuscode").Grouping("StatusCode", strconv.Itoa(statuscode)). // 给指标添加标签，可以添加多个
									Push(); err != nil {
		fmt.Println("Could not push completion time to Pushgateway:", err)
	}

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

func (r *requestHandler) HandleBPFEvent(v []byte, requestMap *RequestMap, spendtimeMap *SpendTimeMap) {
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
		t := time.Now().Unix()
		r.FdMap[ev.Attr.Fd] = &MessageInfo{
			GoTime:     t,
			Time_ns:    ev.Attr.StartNs,
			SocketInfo: ev.Msg,
		}
	case ETSyscallWrite:
		if elem, ok := r.FdMap[ev.Attr.Fd]; ok {
			elem.Buf.Write(ev.Msg)
		}
	case ETSyscallClose:
		if msgInfo, ok := r.FdMap[ev.Attr.Fd]; ok {
			delete(r.FdMap, ev.Attr.Fd)
			msgInfo.Time_ns = ev.Attr.EndNs - msgInfo.Time_ns
			exceli += 1
			parseAndPrintMessage(msgInfo, requestMap, spendtimeMap, exceli)
		} else {
			fmt.Fprintf(os.Stderr, "Missing request with FD: %d\n", ev.Attr.Fd)
			return
		}
	}
}

func (m *RequestMap) addRequestMap(t time.Time, resp *http.Response) {
	m.Lock()
	m.Request[t] = append(m.Request[t], resp) //each timestamp add the resp(including statusCode\len)
	m.Unlock()
}
func (m *SpendTimeMap) addSependTimeMap(t time.Time, ns int64) {
	m.Lock()
	m.SpendTime[t] = append(m.SpendTime[t], ns)
	m.Unlock()
}
func parseAndPrintMessage(msgInfo *MessageInfo, requestMap *RequestMap, spendtimeMap *SpendTimeMap, excelIndex int) {
	resp, err := http.ReadResponse(bufio.NewReader(&msgInfo.Buf), nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to parse request\n")
		return
	}

	requestMap.addRequestMap(time.Unix(msgInfo.GoTime, 0), resp) //each timestamp add the resp(including statusCode\len)
	spendtimeMap.addSependTimeMap(time.Unix(msgInfo.GoTime, 0), msgInfo.Time_ns)

	if prome {
		Histogram_Push(podname, msgInfo.Time_ns, msgInfo.GoTime)
		Gauge_Push(podname, resp.StatusCode, msgInfo.GoTime)
	}
	fmt.Println("resp:   ", resp)
	body := resp.Body
	b, _ := ioutil.ReadAll(body)
	body.Close()
	fmt.Printf("HTTP from %s [%d]:StatusCode: %s, Len: %s, ContentType: %s, Body: %s\n",
		color.BlueString("%s", podname),
		excelIndex-1,
		color.GreenString("%d", resp.StatusCode),
		color.GreenString("%d", resp.ContentLength),
		color.GreenString("%s", resp.Header["Content-Type"]),
		color.GreenString("%s", string(b)))
	f.SetCellValue("Sheet1", "A"+strconv.Itoa(excelIndex), resp.StatusCode)
	f.SetCellValue("Sheet1", "B"+strconv.Itoa(excelIndex), resp.ContentLength)
	f.SetCellValue("Sheet1", "C"+strconv.Itoa(excelIndex), resp.Header["Content-Type"])
	f.SetCellValue("Sheet1", "D"+strconv.Itoa(excelIndex), string(b))

	if excelIndex == 30 { //save logs data
		if err := f.SaveAs("httpserver.xlsx"); err != nil {
			println(err.Error())
		}
	}
}

func (m *RequestMap) readRequestMap() map[time.Time][]*http.Response {
	m.RLock()
	rmap := m.Request
	m.RUnlock()
	return rmap
}
func (m *SpendTimeMap) readSpendTimeMap() map[time.Time][]int64 {
	m.RLock()
	smap := m.SpendTime
	m.RUnlock()
	return smap
}

func PrintStatisticsNumber(requestMap *RequestMap, spendtimeMap *SpendTimeMap) {
	timeTickerChan := time.Tick(time.Second * 10) //每10秒进行一次展示输出
	for {
		rmap := requestMap.readRequestMap()
		smap := spendtimeMap.readSpendTimeMap()
		if len(rmap) != 0 {
			fmt.Println("=============HTTP STATISTICS==================")
			for v := range rmap {
				fmt.Println(v, "时有连接数：", len(rmap[v]))
				fmt.Printf("Status Code:")
				for _, res := range rmap[v] {
					fmt.Printf("%d ", res.StatusCode)
				}
				fmt.Printf("\nSpend Time(ms):")
				for _, ns := range smap[v] {
					fmt.Printf("%d ", ns/1000/1000)
				}
				fmt.Printf("\n")
			}
		}

		<-timeTickerChan
	}
}

func GetHttpViaKprobe(tracePID int, p string) {
	flag.Parse()
	podname = p
	count = 0
	prome = true
	exceli = 1
	prometheus.Register(histogramRegistered)

	statusMap = make(map[int]prometheus.Gauge)
	statusMap[200] = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "http_status_code_200",
		Help: "Current status of the http protocol.",
	})
	statusMap[400] = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "http_status_code_4oo",
		Help: "Current status of the http protocol.",
	})
	statusMap[401] = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "http_status_code_401",
		Help: "Current status of the http protocol.",
	})
	statusMap[404] = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "http_status_code_404",
		Help: "Current status of the http protocol.",
	})
	statusMap[502] = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "http_status_code_502",
		Help: "Current status of the http protocol.",
	})
	statusMap[504] = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "http_status_code_504",
		Help: "Current status of the http protocol.",
	})

	requestMap := &RequestMap{
		Request: make(map[time.Time][]*http.Response),
	}
	spendMap := &SpendTimeMap{
		SpendTime: make(map[time.Time][]int64),
	}

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
	index := f.NewSheet("Sheet1")
	f.SetActiveSheet(index)

	f.SetCellValue("Sheet1", "A1", "StatusCode")
	f.SetCellValue("Sheet1", "B1", "ContentLength")
	f.SetCellValue("Sheet1", "C1", "Content-Type")
	f.SetCellValue("Sheet1", "D1", "body")
	//go PrintStatisticsNumber(requestMap, spendMap)
	for {
		select {
		case <-intCh:
			fmt.Println("Terminating")
			os.Exit(0)
		case v := <-ch:
			requestHander.HandleBPFEvent(v, requestMap, spendMap)
		}
	}
}
