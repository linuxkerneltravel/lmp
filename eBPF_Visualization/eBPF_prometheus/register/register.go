package register

import (
	"github.com/prometheus/client_golang/prometheus"

	"ebpf-prom/collector"
)

func Register() *prometheus.Registry {
	worker := collector.NewClusterManger("test_vfsstat")
	reg := prometheus.NewPedanticRegistry()
	reg.MustRegister(worker)
	return reg
}
