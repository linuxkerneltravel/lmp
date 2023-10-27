package metrics

import (
	"fmt"
	"os"
	"testing"
)

func TestNodeExporterMetric(t *testing.T) {
	if os.ExpandEnv("GITHUB_ACTIONS") != "" {
		return
	}
	promHost, err := GetPromHost()
	if err != nil {
		t.Errorf("%s", err)
	}
	cm := NodeExporterClusterMetrics{}
	a, err := cm.GetLoad1Data(promHost)
	if err != nil {
		t.Errorf("%s", err)
		return
	}
	for s, f := range a {
		fmt.Println(s, f)
	}
}
