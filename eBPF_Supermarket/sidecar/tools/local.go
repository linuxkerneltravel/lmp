package tools

import (
	"fmt"
	"os"

	"github.com/shirou/gopsutil/v3/process"
)

// FileExists checks if a file exists
func FileExists(filePath string) bool {
	fileInfo, err := os.Stat(filePath)
	if err == nil && fileInfo.IsDir() == false {
		return true
	}
	return false
}

// GetNodeName gets local machine's hostname, aka node name
func GetNodeName() (string, error) {
	// adaptation for minikube
	if IsInMinikubeMode() {
		return "minikube", nil
	}

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
