package visualization

import (
	"fmt"
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// VisPort is the service port for exporter
var VisPort = "8765"

func GetNewSummaryVec(name string, help string, constLabels map[string]string, labelNames []string) *prometheus.SummaryVec {
	return prometheus.NewSummaryVec(
		prometheus.SummaryOpts{
			Name:        name,
			Help:        help,
			ConstLabels: constLabels,
			Objectives:  map[float64]float64{0.1: 0.01, 0.25: 0.05, 0.5: 0.05, 0.9: 0.01, 0.99: 0.001, 0.999: 0.0001},
		},
		labelNames)
}

func GetNewHistogramVec(name string, help string, constLabels map[string]string, labelNames []string) *prometheus.HistogramVec {
	return prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:        name,
			Help:        help,
			ConstLabels: constLabels,
		},
		labelNames)
}

func GetNewCounterVec(name string, help string, constLabels map[string]string, labelNames []string) *prometheus.CounterVec {
	return prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name:        name,
			Help:        help,
			ConstLabels: constLabels,
		},
		labelNames)
}

func GetNewGaugeVec(name string, help string, constLabels map[string]string, labelNames []string) *prometheus.GaugeVec {
	return prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name:        name,
			Help:        help,
			ConstLabels: constLabels,
		},
		labelNames)
}

func StratExporter() {
	http.Handle("/metrics", promhttp.Handler())
	fmt.Println("Exporter at: http://0.0.0.0:" + VisPort)
	http.ListenAndServe("0.0.0.0:"+VisPort, nil)
}
