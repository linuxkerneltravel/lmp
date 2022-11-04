package kernel

import (
	"fmt"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/linuxkerneltravel/lmp/eBPF_Supermarket/kernel_and_user_pod_observation/bpf/nic_throughput"
	"github.com/linuxkerneltravel/lmp/eBPF_Supermarket/sidecar/visualization"
)

func updateMetric(vec *prometheus.GaugeVec, labels map[string]string, value float64) {
	if value < 0 {
		return
	}
	summary, err := vec.GetMetricWith(labels)
	if err == nil {
		summary.Set(value)
	} else {
		fmt.Println(err)
	}
}

func GetNicThroughputMetric(vethName string) {
	nicLabel := []string{"dir"}
	nic_AVG := visualization.GetNewGaugeVec("nic_AVG", "", map[string]string{}, nicLabel)
	nic_BPS := visualization.GetNewGaugeVec("nic_BPS", "", map[string]string{}, nicLabel)
	nic_PPS := visualization.GetNewGaugeVec("nic_PPS", "", map[string]string{}, nicLabel)

	prometheus.MustRegister(nic_AVG)
	prometheus.MustRegister(nic_BPS)
	prometheus.MustRegister(nic_PPS)

	nicChan := make(chan nic_throughput.Event, 10000)
	go nic_throughput.Probe(vethName, nicChan)

	for {
		v := <-nicChan
		// got NicThroughputEvent
		fmt.Println("got NicThroughput Event:", v)
		// process event
		updateMetric(nic_AVG, map[string]string{"dir": v.Dir}, float64(v.Avg))
		updateMetric(nic_BPS, map[string]string{"dir": v.Dir}, float64(v.BPS))
		updateMetric(nic_PPS, map[string]string{"dir": v.Dir}, float64(v.PPS))
		// fmt.Println("NicThroughputEvent done")
	}
}
