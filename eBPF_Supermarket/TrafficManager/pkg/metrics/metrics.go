package metrics

type Metric interface {
}

type NodeMetric interface {
	Update(cm ClusterMetric) error
	AvailableRate() float64
}

type ClusterMetric interface {
	Update() error
	AvailableRate() float64
	Query(name string) Metric
}
