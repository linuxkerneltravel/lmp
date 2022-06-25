package container

import (
	"fmt"
	"time"

	"github.com/shirou/gopsutil/v3/cpu"
	"github.com/shirou/gopsutil/v3/process"
)

// GetProcessCpuTimeStat gets CPU times of the process
func GetProcessCpuTimeStat(p *process.Process) (*cpu.TimesStat, error) {
	return p.Times()
}

// getProcessCpuUsageRate calculates process CPU usage rate for a interval
func getProcessCpuUsageRate(oldStat cpu.TimesStat, newStat cpu.TimesStat, duration time.Duration) float64 {
	secondInterval := float64(duration / time.Second)
	fmt.Println(secondInterval)
	return ((newStat.User + newStat.System) - (oldStat.User + oldStat.System)) / secondInterval
}

// GetProcessCpuUsagePercentage calculates process CPU usage percentage for a interval
func GetProcessCpuUsagePercentage(oldStat cpu.TimesStat, newStat cpu.TimesStat, duration time.Duration) float64 {
	return getProcessCpuUsageRate(oldStat, newStat, duration) * 100
}
