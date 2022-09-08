package tools

import (
	"bufio"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/shirou/gopsutil/v3/process"
)

var MinikubePid = -1

var ppidAndPid map[int]map[int]int

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

// findChildProcessesFromProcFileSystem gets PIDs under ppid's namespace
func findChildProcessesFromProcFileSystem(ppid, pid int) ([]int, error) {
	pattern := fmt.Sprintf("/proc/%d/root/proc", ppid)
	files, err := os.ReadDir(pattern)
	if err != nil {
		return nil, fmt.Errorf("got children process failed by proc: %s", err)
	}

	var res []int

	for _, file := range files {
		if num, err := strconv.Atoi(file.Name()); err == nil {
			file, err := os.Open(filepath.Join(pattern, file.Name(), "status"))
			if err != nil {
				panic(err)
			}
			defer file.Close()
			content, _ := ioutil.ReadAll(file)
			reg, _ := regexp.Compile("PPid:[\\s]*[0-9]*")
			regRes := reg.FindString(string(content[:]))
			regRes = strings.Replace(regRes, "PPid:", "", 1)
			regRes = strings.Trim(regRes, " \t")

			getPpid, _ := strconv.Atoi(regRes)
			if getPpid == pid {
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

func getNsPidList(statusPath string) ([]int, error) {
	file, err := os.Open(statusPath)
	if err != nil {
		panic(err)
	}
	defer file.Close()
	content, _ := ioutil.ReadAll(file)

	reg, _ := regexp.Compile("NSpid:.*")
	regRes := reg.FindString(string(content[:]))
	regRes = strings.Replace(regRes, "NSpid:", "", 1)
	regRes = strings.Trim(regRes, " \t")

	var res []int

	for _, s := range strings.Split(regRes, "\t") {
		i, _ := strconv.Atoi(s)
		res = append(res, i)
	}

	return res, nil
}

func GetPidUnderRootPidNamespace(ppid, pid int) (int, error) {
	if ppidAndPid == nil {
		ppidAndPid = make(map[int]map[int]int)
	}
	_, ok := ppidAndPid[ppid]
	if ok == false {
		ppidAndPid[ppid] = make(map[int]int)
		var allProcessUnderPp []*process.Process
		pp, err := process.NewProcess(int32(ppid))
		if err != nil {
			return -1, fmt.Errorf("no process PID=%d: %s", ppid, err)
		}
		cs, _ := pp.Children()
		allProcessUnderPp = append(allProcessUnderPp, cs...)
		for _, c := range cs {
			ccs, _ := c.Children()
			allProcessUnderPp = append(allProcessUnderPp, ccs...)
		}

		for _, cp := range allProcessUnderPp {
			pattern := fmt.Sprintf("/proc/%d/status", cp.Pid)
			res, _ := getNsPidList(pattern)
			if len(res) > 1 {
				ppidAndPid[ppid][res[1]] = res[0]
			}
		}
	}

	res, ok := ppidAndPid[ppid][pid]

	if ok {
		return res, nil
	} else {
		fmt.Println(ppidAndPid)
		return -1, fmt.Errorf("process %d under %d not found", pid, ppid)
	}
}

// DetectCgroupPath returns the first-found mount point of type cgroup2
func DetectCgroupPath() (string, error) {
	f, err := os.Open("/proc/mounts")
	if err != nil {
		return "", err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		// example fields: cgroup2 /sys/fs/cgroup/unified cgroup2 rw,nosuid,nodev,noexec,relatime 0 0
		fields := strings.Split(scanner.Text(), " ")
		if len(fields) >= 3 && fields[2] == "cgroup2" {
			return fields[1], nil
		}
	}

	return "", fmt.Errorf("cgroup2 not mounted")
}
