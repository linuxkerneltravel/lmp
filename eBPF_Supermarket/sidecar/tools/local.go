package tools

import (
	"fmt"
	"os"
	"strconv"

	"github.com/shirou/gopsutil/v3/process"
)

var MinikubePid = -1

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

func fromIntToProcess(pidList []int) []*process.Process {
	var res []*process.Process
	for _, pid := range pidList {
		res = append(res, &process.Process{Pid: int32(pid)})
	}
	return res
}

func findChildProcessesFromProcFileSystem(ppid, pid int) ([]int, error) {
	pattern := fmt.Sprintf("/proc/%d/root/proc/%d/root/proc", ppid, pid)
	files, err := os.ReadDir(pattern)
	if err != nil {
		return nil, fmt.Errorf("got children process failed by proc: %s", err)
	}

	var res []int

	for _, file := range files {
		if num, err := strconv.Atoi(file.Name()); err == nil {
			if num != 1 {
				res = append(res, num)
			}
		}
	}
	return res, nil
}

func FindChildProcessesUnderMinikubeWithDockerDriver(pid int) ([]*process.Process, error) {
	if MinikubePid < 0 {
		return nil, fmt.Errorf("minikube uninitialized")
	}

	pidList, err := findChildProcessesFromProcFileSystem(MinikubePid, pid)

	return fromIntToProcess(pidList), err
}
