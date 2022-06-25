package tools

import (
	"fmt"
	"os"

	"github.com/shirou/gopsutil/v3/process"
)

// GetNodeName gets local machine's hostname, aka node name
func GetNodeName() (string, error) {
	nodeName, err := os.Hostname()
	if err != nil {
		return "", fmt.Errorf("cannot get hostname from local machine: %s", err)
	}
	return nodeName, nil
}

// FindChildProcesses finds child process(es) from a parent process. Return nil for empty
func FindChildProcesses(parentProcess *process.Process) ([]*process.Process, error) {
	childrenProcess, err := parentProcess.Children()
	if err != nil {
		return nil, err
	}

	return childrenProcess, nil
}
