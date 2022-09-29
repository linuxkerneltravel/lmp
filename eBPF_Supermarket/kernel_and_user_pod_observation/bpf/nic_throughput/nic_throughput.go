package nic_throughput

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"time"

	"github.com/iovisor/gobpf/bcc"
)

import "C"

const source string = `
#include <linux/netdevice.h>
#include <linux/ethtool.h>

#if IFNAMSIZ != 16 
#error "IFNAMSIZ != 16 is not supported"
#endif
#define MAX_QUEUE_NUM 1024

union name_buf{
    char name[IFNAMSIZ];
    struct {
        u64 hi;
        u64 lo;
    }name_int;
};

/* data retrieved in tracepoints */
struct queue_data{
    u64 total_pkt_len;
    u64 num_pkt;
};

/* array of length 1 for device name */
// BPF_HASH(name_map, u64, union name_buf);
union name_buf name_input = {.name = {"__NAME__"}};

/* table for transmit & receive packets */
BPF_HASH(tx_q, u16, struct queue_data, MAX_QUEUE_NUM);
BPF_HASH(rx_q, u16, struct queue_data, MAX_QUEUE_NUM);

static inline int name_filter(struct sk_buff* skb){
    /* get device name from skb */
    union name_buf real_devname;
    struct net_device *dev;

    bpf_probe_read(&dev, sizeof(skb->dev), ((char *)skb+offsetof(struct sk_buff, dev)));
    bpf_probe_read(&real_devname.name, IFNAMSIZ, dev->name);

    if(name_input.name_int.hi != real_devname.name_int.hi || name_input.name_int.lo != real_devname.name_int.lo){
        return 0;
    }

    return 1;
}

static void updata_data(struct queue_data *data, u64 len){
    data->total_pkt_len += len;
    data->num_pkt ++;
}

TRACEPOINT_PROBE(net, net_dev_start_xmit){
    /* read device name */
    struct sk_buff* skb = (struct sk_buff*)args->skbaddr;
    if(!name_filter(skb)){
        return 0;
    }

    /* update table */
    u16 qid = skb->queue_mapping;
    struct queue_data newdata;
    __builtin_memset(&newdata, 0, sizeof(newdata));
    struct queue_data *data = tx_q.lookup_or_try_init(&qid, &newdata);
    if(!data){
        return 0;
    }
    updata_data(data, skb->len);
    
    return 0;
}

TRACEPOINT_PROBE(net, netif_receive_skb){
    struct sk_buff skb;

    bpf_probe_read(&skb, sizeof(skb), args->skbaddr);
    if(!name_filter(&skb)){
        return 0;
    }

    u16 qid = 0;
    if (skb_rx_queue_recorded(&skb))
        qid = skb_get_rx_queue(&skb);

    struct queue_data newdata;
    __builtin_memset(&newdata, 0, sizeof(newdata));
    struct queue_data *data = rx_q.lookup_or_try_init(&qid, &newdata);
    if(!data){
        return 0;
    }
    updata_data(data, skb.len);
    
    return 0;
}
`

type queueData struct {
	Total_pkt_len uint64
	Num_pkt       uint64
}

type Event struct {
	Time time.Time `json:"Time,omitempty"`
	Dir  string    `json:"Dir"`
	Avg  float32   `json:"Avg"`
	BPS  float32   `json:"BPS"`
	PPS  float32   `json:"PPS"`
}

func (e Event) Print() {
	fmt.Println("╔======TCP connect begin====╗")
	fmt.Println("Time :", e.Time.String())
	fmt.Println("Dir  :", e.Dir)
	fmt.Println("Avg  :", e.Avg)
	fmt.Println("BPS  :", e.BPS)
	fmt.Println("PPS  :", e.PPS)
	fmt.Println("╚======TCP connect end======╝")
}


func getEventFromData(dir string, table *bcc.Table, interval float32) Event {
	var tBPS, tPPS, tAVG, tpkt, tlen float32 = 0, 0, 0, 0, 0
	var data queueData

	for iter := table.Iter(); iter.Next(); {
		err := binary.Read(bytes.NewBuffer(iter.Leaf()), bcc.GetHostByteOrder(), &data)
		if err != nil {
			fmt.Printf("failed to decode received data: %s\n", err)
			continue
		}
		tlen += float32(data.Total_pkt_len)
		tpkt += float32(data.Num_pkt)
	}

	tBPS = tlen / interval
	tPPS = tpkt / interval

	if tpkt != 0 {
		tAVG = tlen / tpkt
	}

	goEvent := Event{
		Time: time.Now(),
		Dir:  dir,
		Avg:  tAVG,
		BPS:  tBPS,
		PPS:  tPPS,
	}

	return goEvent
}


func Probe(vethName string, ch chan<- Event) {

	sourceBpf := source
	sourceBpf = strings.Replace(sourceBpf, "__NAME__", vethName, 1)

	m := bcc.NewModule(sourceBpf, []string{})
	defer m.Close()

	txqTrace, err := m.LoadTracepoint("tracepoint__net__net_dev_start_xmit")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load net:net_dev_start_xmit: %s\n", err)
		os.Exit(1)
	}

	err = m.AttachTracepoint("net:net_dev_start_xmit", txqTrace)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to attach net:net_dev_start_xmit: %s\n", err)
		os.Exit(1)
	}

	tableTX := bcc.NewTable(m.TableId("tx_q"), m)
	tableRX := bcc.NewTable(m.TableId("rx_q"), m)

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, os.Kill)

	var interval int = 1

	fmt.Println("NIC Throughput started!")
	go func() {
		for {
			time.Sleep(time.Duration(interval) * time.Second)

			txEvent := getEventFromData("TX", tableTX, float32(interval))
			rxEvent := getEventFromData("RX", tableRX, float32(interval))

			ch <- txEvent
			ch <- rxEvent

			tableTX.DeleteAll()
			tableRX.DeleteAll()
		}
	}()

	<-sig

}
