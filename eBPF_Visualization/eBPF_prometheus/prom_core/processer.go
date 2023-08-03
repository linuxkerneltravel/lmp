package prom_core

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"log"
	"net/http"
	"strconv"
	"sync"
)

type MyMetrics struct {
	mu   sync.Mutex
	maps map[string]interface{}
}

func (m *MyMetrics) Describe(ch chan<- *prometheus.Desc) {
	ch <- prometheus.NewDesc(
		"bpf_metrics",
		"collect data and load to metrics",
		[]string{"bpf_out_data"},
		nil,
	)
}

// Convert_Maps_To_Dict shift dict list to dict
func Convert_Maps_To_Dict(maps []map[string]interface{}) map[string]interface{} {
	new_Dict := make(map[string]interface{})
	for _, dict := range maps {
		for key, value := range dict {
			new_Dict[key] = value
		}
	}
	return new_Dict
}

// Format_Dict format dict.
func Format_Dict(dict map[string]interface{}) map[string]float64 {
	new_dict := map[string]float64{}
	for key, value := range dict {
		if strvalue, is_string := value.(string); is_string {
			// shift numerical data to float64
			if floatValue, err := strconv.ParseFloat(strvalue, 64); err == nil {
				new_dict[key] = floatValue
			} else {
				// todo: what should do when get string data.
			}
		}
	}
	return new_dict
}

// Collect func collect data and load to metrics.
func (m *MyMetrics) Collect(ch chan<- prometheus.Metric) {
	bpfdata := Format_Dict(m.maps)
	for key, value := range bpfdata {
		ch <- prometheus.MustNewConstMetric(
			prometheus.NewDesc(
				"bpf_metrics",
				"collect data and load to metrics",
				[]string{"bpf_out_data"},
				nil,
			),
			prometheus.GaugeValue,
			value,
			key,
		)
	}
}

// StartService get map list chan and run a service to show metrics
func StartService(maps_chan chan []map[string]interface{}) {
	bpfMetrics := &MyMetrics{
		maps: make(map[string]interface{}),
	}
	prometheus.MustRegister(bpfMetrics)

	http.Handle("/metrics", promhttp.Handler())
	go func() {
		if err := http.ListenAndServe(":8090", nil); err != nil {
			log.Fatalf("Failed to start HTTP server:", err)
		}
	}()

	go func() {
		for {
			bpfMetrics.mu.Lock()
			map_list := <-maps_chan
			dict := Convert_Maps_To_Dict(map_list)
			for key, value := range dict {
				bpfMetrics.maps[key] = value
			}
			bpfMetrics.mu.Unlock()
		}
	}()
	select {}
}
