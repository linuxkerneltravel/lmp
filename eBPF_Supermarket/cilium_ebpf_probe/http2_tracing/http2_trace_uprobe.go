package http2_tracing

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"github.com/fatih/color"
	"github.com/iovisor/gobpf/bcc"
	"os"
	"os/signal"
	"strings"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/push"
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

type writeHeaderEvent struct {
	Headerevent [2]http2HeaderEvent
	Ns          int64
}
type operatorHeaderEvent struct {
	Headerevent [8]http2HeaderEvent
	Ns          int64
}

//these two for channel
type beginTimeEvent struct {
	T  int64 //时间戳
	Ns int64 //time in kernel
}
type endTimeEvent struct {
	StatusCode string //statusecode
	Ns         int64  //time in kernel
}

//this for map [time.Time][status]
type perTimeStatus struct {
	Statuscode string
	SpendTime  int64
}

//this for mutex map
type PerStatusWithLock struct {
	sync.RWMutex
	perStatus map[time.Time][]perTimeStatus
}

func formatHeaderField(field headerField) string {
	return string(field.Msg[0:field.Size])
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
	binaryProg          string
	symbol              string
	probeFn             string
	beginch             chan beginTimeEvent
	endch               chan endTimeEvent
	pn                  string
	histogramRegistered = prometheus.NewHistogram(
		prometheus.HistogramOpts{
			Name:    "grpc_spend",
			Help:    "A histogram of normally distributed gprc spend time(ns).",
			Buckets: prometheus.LinearBuckets(0, 800, 20),
		},
	)
	Gauge = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "grpc_status",
		Help: "grpc status code count.",
	})
)

//
//func init() {
//	flag.StringVar(&binaryProg, "binary", "", "The binary to probe")
//}

func parseToSturctFromChannel(m *PerStatusWithLock) {

	for {
		select {
		case bv := <-beginch:
			ev := <-endch
			m.addPerMap(time.Unix(bv.T, 0),
				perTimeStatus{Statuscode: ev.StatusCode, SpendTime: (ev.Ns - bv.Ns) / 1000}) // /1000 is ns
			//to histogram
			histogramRegistered.Observe(float64((ev.Ns - bv.Ns) / 1000))
			if err := push.New("http://10.10.103.122:9091", "GRPCSpend"). // push.New("pushgateway地址", "job名称")
											Collector(histogramRegistered).                            //gotime.Format("2006-01-02 15:04:05")                                                                                                  // Collector(completionTime) 给指标赋值
											Grouping("podname", pn).Grouping("instance", "spendtime"). // 给指标添加标签，可以添加多个
											Push(); err != nil {
				fmt.Println("Could not push completion time to Pushgateway:", err)
			}
			// to gauge
			Gauge.Add(1)
			if err := push.New("http://10.10.103.122:9091", "GRPCStatus"). // push.New("pushgateway地址", "job名称")
											Collector(Gauge).                                                                           //gotime.Format("2006-01-02 15:04:05")                                                                                                  // Collector(completionTime) 给指标赋值
											Grouping("podname", pn).Grouping("instance", "statuscode").Grouping("gRpcStatusCode", "0"). // 给指标添加标签，可以添加多个
											Push(); err != nil {
				fmt.Println("Could not push completion time to Pushgateway:", err)
			}
		}
	}
}
func (m *PerStatusWithLock) addPerMap(t time.Time, s perTimeStatus) {
	m.Lock()
	m.perStatus[t] = append(m.perStatus[t], s) //each timestamp add the resp(including statusCode\len)
	m.Unlock()
}
func (m *PerStatusWithLock) readPerMap() map[time.Time][]perTimeStatus {
	m.RLock()
	rmap := m.perStatus
	m.RUnlock()
	return rmap
}
func PrintStaticsNumber(m *PerStatusWithLock) {
	timeTickerChan := time.Tick(time.Second * 20)
	for {
		rmap := m.readPerMap()
		if len(rmap) != 0 {
			fmt.Println("**************HTTP2 STATISTICS**************")
			for v := range rmap {
				fmt.Println(v, "时有连接数： ", len(rmap[v]))
				for _, value := range rmap[v] {
					fmt.Printf("Status Code:%s Time(ns):%d \n", value.Statuscode, value.SpendTime)
				}
			}
		}

		<-timeTickerChan
	}
}

func GetHttp2ViaUprobe(binaryProg string, podname string) {
	//flag.Parse()
	if len(binaryProg) == 0 {
		panic("Argument --binary needs to be specified")
	}
	pn = podname
	prometheus.Register(histogramRegistered)

	fmt.Println("Attach 1 uprobe on ", binaryProg)
	bccMod := bcc.NewModule(bpfProgram, []string{})
	const loopWriterWriteHeaderSymbol = "google.golang.org/grpc/internal/transport.(*loopyWriter).writeHeader"
	const loopWriterWriteHeaderProbeFn = "probe_loopy_writer_write_header"
	mustAttachUprobe(bccMod, binaryProg, loopWriterWriteHeaderSymbol, loopWriterWriteHeaderProbeFn)

	const http2ServerOperateHeadersSymbol = "google.golang.org/grpc/internal/transport.(*http2Server).operateHeaders"
	const http2ServerOperateHeadersProbeFn = "probe_http2_server_operate_headers"
	mustAttachUprobe(bccMod, binaryProg, http2ServerOperateHeadersSymbol, http2ServerOperateHeadersProbeFn)
	//
	//const handleStreamSymbol = "google.golang.org/grpc.(*Server).handleStream"
	//const handleStreamProbeFn = "probe_handleStream"
	//mustAttachUprobe(bccMod, binaryProg, handleStreamSymbol, handleStreamProbeFn)
	//
	//const sendResponseSymbol = "google.golang.org/grpc.(*Server).sendResponse"
	//const sendResponseProbeFn = "probe_sendResponse"
	//mustAttachUprobe(bccMod, binaryProg, sendResponseSymbol, sendResponseProbeFn)

	fmt.Println("uprobe for http2 grpc begin...")
	defer func() {
		bccMod.Close()
	}()

	table := bcc.NewTable(bccMod.TableId("write_header_events"), bccMod)
	ch := make(chan []byte)
	pm, err := bcc.InitPerfMap(table, ch, nil)
	if err != nil {
		panic(err)
	}

	operatormap := bcc.NewTable(bccMod.TableId("operator_header_events"), bccMod)
	ch2 := make(chan []byte)
	pm2, err := bcc.InitPerfMap(operatormap, ch2, nil)
	if err != nil {
		panic(err)
	}

	// Watch Ctrl-C so we can quit this program.
	intCh := make(chan os.Signal, 1)
	signal.Notify(intCh, os.Interrupt)

	pm.Start()
	defer pm.Stop()

	pm2.Start()
	defer pm2.Stop()

	beginch = make(chan beginTimeEvent, 1000)
	endch = make(chan endTimeEvent, 1000)

	perstatusmap := &PerStatusWithLock{perStatus: make(map[time.Time][]perTimeStatus)}
	tmp := endTimeEvent{}
	go parseToSturctFromChannel(perstatusmap)
	//go PrintStaticsNumber(perstatusmap)
	for {
		select {
		case <-intCh:
			fmt.Println("Terminating")
			os.Exit(0)
		case v2 := <-ch2: //operator on begin
			var parsed2 operatorHeaderEvent
			if err := binary.Read(bytes.NewBuffer(v2), bcc.GetHostByteOrder(), &parsed2); err != nil {
				panic(err)
			}
			fmt.Printf("%s \n", color.BlueString("%s", "data from grpc received"))
			for _, v := range parsed2.Headerevent {
				fmt.Printf("[%s]=%s;", formatHeaderField(v.Name), color.GreenString("%s", formatHeaderField(v.Value)))
			}
			fmt.Printf("\n")
			beginch <- beginTimeEvent{T: time.Now().Unix(), Ns: parsed2.Ns} //add to begin
		case v1 := <-ch: //write on end

			var parsed writeHeaderEvent
			if err := binary.Read(bytes.NewBuffer(v1), bcc.GetHostByteOrder(), &parsed); err != nil {
				panic(err)
			}

			fmt.Printf("%s \n", color.BlueString("%s", "data from grpc header to send"))

			for _, v := range parsed.Headerevent {

				if strings.EqualFold(formatHeaderField(v.Name), ":status") {
					tmp.StatusCode = formatHeaderField(v.Value)
				}
				fmt.Printf("[%s]=%s；", formatHeaderField(v.Name), color.GreenString("%s", formatHeaderField(v.Value)))
			}
			if parsed.Ns != 0 {
				tmp.Ns = parsed.Ns
				endch <- tmp // add to end chan
			}
			fmt.Printf("\n")
		}
	}
}
