package metrics

import (
	"context"
	"fmt"
	"log"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/prometheus/client_golang/api"
	"github.com/prometheus/client_golang/api/prometheus/v1"
	"github.com/prometheus/common/model"
)

type NodeExporterMetric struct {
	Load1 float64
}

type NodeExporterNodeMetric struct {
	name  string
	load1 float64
	mu    sync.Mutex
}

func (nm *NodeExporterNodeMetric) Update(metric ClusterMetric) error {
	nm.mu.Lock()
	defer nm.mu.Unlock()
	nm.load1 = metric.Query(nm.name).(NodeExporterNodeMetric).load1
	return nil
}

func (nm *NodeExporterNodeMetric) AvailableRate() float64 {
	if nm.load1 > 10 {
		return 0
	} else {
		return (10 - nm.load1) / 10
	}
}

type NodeExporterClusterMetrics struct {
	Address string
	load1   float64
	data    map[string]float64
	mu      sync.Mutex
}

func (cm *NodeExporterClusterMetrics) Update() error {
	log.Printf("[INFO] Fetching Node Exporter data...")
	load1Data, err := cm.GetLoad1Data(cm.Address)
	if err != nil {
		return fmt.Errorf("error fetching load1 data: %v", err)
	}
	cm.mu.Lock()
	cm.data = load1Data
	cm.mu.Unlock()
	return nil
}

func (cm *NodeExporterClusterMetrics) AvailableRate() float64 {
	return 1
}

func (cm *NodeExporterClusterMetrics) Query(name string) Metric {
	cm.mu.Lock()
	defer cm.mu.Unlock()
	return NodeExporterNodeMetric{name: name, load1: cm.data[name], mu: sync.Mutex{}}
}

func (cm *NodeExporterClusterMetrics) GetLoad1Data(prometheusAddress string) (map[string]float64, error) {
	client, err := api.NewClient(api.Config{
		Address: prometheusAddress,
	})
	if err != nil {
		return nil, err
	}

	query := `avg_over_time(node_load1{job="node-exporter"}[1m])`

	promAPI := v1.NewAPI(client)
	result, _, err := promAPI.QueryRange(
		context.TODO(),
		query,
		v1.Range{Start: time.Now().Add(-1 * time.Minute), End: time.Now(), Step: time.Minute},
	)
	if err != nil {
		return nil, err
	}

	load1Data := make(map[string]float64)
	matrix, ok := result.(model.Matrix)
	if !ok {
		return nil, fmt.Errorf("unexpected result type")
	}
	totalLoad1 := 0.0
	for _, sample := range matrix {
		node := strings.Replace(string(sample.Metric["instance"]), ":9100", "", 1)
		load1 := float64(sample.Values[0].Value)
		totalLoad1 += load1
		load1Data[node] = load1
	}

	cm.load1 = totalLoad1
	return load1Data, nil
}

func GetPromHost() (string, error) {
	// command := `kubectl get nodes -o=jsonpath='{.items[?(@.metadata.labels.node-role\.kubernetes\.io/control-plane=="")].status.addresses[?(@.type=="InternalIP")].address}'`
	cmd := exec.Command("kubectl", "get", "nodes", "-o=jsonpath={.items[?(@.metadata.labels.node-role\\.kubernetes\\.io/control-plane==\"\")].status.addresses[?(@.type==\"InternalIP\")].address}")

	output, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("error executing kubectl command: %s", err)
	}

	address := strings.Trim(string(output), " \n")
	promHost := fmt.Sprintf("http://%s:9090", address)
	fmt.Println("Prometheus URL:", promHost)
	return promHost, nil
}
