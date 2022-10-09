package register

import (
	"example.com/m/v2/collector"
	"github.com/prometheus/client_golang/prometheus"
)

func Register() *prometheus.Registry {
	worker := collector.NewClusterManger("test_vfsstat")
	reg := prometheus.NewPedanticRegistry()
	reg.MustRegister(worker)
	return reg
}
