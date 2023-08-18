// Copyright 2023 The LMP Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// https://github.com/linuxkerneltravel/lmp/blob/develop/LICENSE
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// author: Gui-Yue
//
// Prometheus可视化的核心逻辑，实现将规范化的数据加载到Prometheus的metrics中，并启动http服务，供Prometheus-Service提取。

package prom_core

import (
	"ebpf_prometheus/checker"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"log"
	"net/http"
	"strconv"
	"strings"
	"sync"
)

type MyMetrics struct {
	mu   sync.Mutex
	maps map[string]interface{}
}

func (m *MyMetrics) Describe(ch chan<- *prometheus.Desc) {}

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
func Format_Dict(dict map[string]interface{}) (map[string]float64, map[string]string) {
	measurable_dict := map[string]float64{}
	string_dict := map[string]string{}
	for key, value := range dict {
		if strvalue, is_string := value.(string); is_string {
			// shift numerical data to float64
			if floatValue, err := strconv.ParseFloat(strvalue, 64); err == nil {
				measurable_dict[key] = floatValue
			} else {
				if checker.Isinvalid(key) || strings.ToUpper(key) == "TIME" || strings.ToUpper(key) == "SOCK" {
					continue
				}
				string_dict[key] = value.(string)
			}
		}
	}
	return measurable_dict, string_dict
}

// Collect func collect data and load to metrics.
func (m *MyMetrics) Collect(ch chan<- prometheus.Metric) {
	bpfdata, stringdata := Format_Dict(m.maps)
	for key, value := range bpfdata {
		ch <- prometheus.MustNewConstMetric(
			prometheus.NewDesc(
				"bpf_metrics",
				"collect data and load to metrics",
				[]string{"bpf_out_data"},
				stringdata,
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
