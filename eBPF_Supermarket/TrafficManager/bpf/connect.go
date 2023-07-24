package bpf

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -target bpf -cflags "-D__TARGET_ARCH_x86" bpf_connect connect.c -- -I./headers

import (
	"bufio"
	"fmt"
	"os"
	"os/signal"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

const MapsPinPath = "/sys/fs/bpf/sock_ops_map"

type Programs struct {
	connectObj    bpf_connectObjects
	connectCgroup link.Link
	backEndSet    map[int]bool
	currentIndex  int
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

func LoadProgram() (Programs, error) {
	var programs Programs
	var options ebpf.CollectionOptions
	options.Maps.PinPath = MapsPinPath

	// Allow the current process to lock memory for eBPF resources.
	err := rlimit.RemoveMemlock()
	if err != nil {
		fmt.Println("[ERROR] Setting limit failed:", err)
		return Programs{}, fmt.Errorf("setting limit failed: %s", err)
	}

	err = os.Mkdir(MapsPinPath, os.ModePerm)
	if err != nil {
		fmt.Println(err)
	}

	err = loadBpf_connectObjects(&programs.connectObj, &options)
	if err != nil {
		return Programs{}, fmt.Errorf("error load objects: %s\n", err)
	}

	programs.backEndSet = make(map[int]bool)
	programs.currentIndex = 0

	return programs, err
}

func (p *Programs) Attach() error {
	fmt.Println("Socket redirect started!")

	cgroupPath, err := DetectCgroupPath()
	if err != nil {
		return fmt.Errorf("detect cgroup path failed: %s", err)
	}

	p.connectCgroup, err = link.AttachCgroup(link.CgroupOptions{
		Path:    cgroupPath,
		Attach:  ebpf.AttachCGroupInet4Connect,
		Program: p.connectObj.bpf_connectPrograms.Sock4Connect,
	})
	if err != nil {
		return fmt.Errorf("error attaching connect to cgroup: %s", err)
	}

	return nil
}

func (p *Programs) Close() {
	fmt.Println("Exiting...")

	if p.connectCgroup != nil {
		fmt.Printf("Closing connect cgroup...\n")
		p.connectCgroup.Close()
	}

	_ = os.Remove(MapsPinPath)
}

func Sample() {
	progs, err := LoadProgram()
	if err != nil {
		fmt.Println("[ERROR] Loading program failed:", err)
		return
	}

	err = progs.Attach()
	if err != nil {
		fmt.Println("[ERROR] Attaching failed:", err)
	}
	defer progs.Close()

	c := make(chan os.Signal, 1)
	signal.Notify(c)
	<-c
}
