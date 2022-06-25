package node

import (
	"time"

	"github.com/shirou/gopsutil/v3/cpu"
)

// GetNodeCpuUsage works as a placeholder for this file
func GetNodeCpuUsage() ([]float64, error) {
	return cpu.Percent(time.Second, true)
}
