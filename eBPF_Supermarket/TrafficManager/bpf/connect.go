// Copyright 2023 The LMP Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// https://github.com/linuxkerneltravel/lmp/blob/develop/LICENSE
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// author: Woa <me@wuzy.cn>

package bpf

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -target bpf -cflags "-D__TARGET_ARCH_x86" bpf_connect connect.c -- -I./headers

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/u8proto"
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

	if p.connectObj.bpf_connectMaps.LB4SERVICES_MAP_V2 != nil {
		p.connectObj.bpf_connectMaps.LB4SERVICES_MAP_V2.Unpin()
		p.connectObj.bpf_connectMaps.LB4SERVICES_MAP_V2.Close()
		fmt.Println("Unpin and close")
	}

	if p.connectObj.bpf_connectMaps.LB4BACKEND_MAP_V2 != nil {
		p.connectObj.bpf_connectMaps.LB4BACKEND_MAP_V2.Unpin()
		p.connectObj.bpf_connectMaps.LB4BACKEND_MAP_V2.Close()
		fmt.Println("Unpin and close")
	}

	_ = os.Remove(MapsPinPath)
}

func Sample() {
	progs, err := LoadProgram()
	if err != nil {
		fmt.Println("[ERROR] Loading program failed:", err)
		return
	}

	// set service
	serviceIP := "1.1.1.1"
	servicePort := 80
	backendNumber := 2
	svcKey := NewService4Key(net.ParseIP(serviceIP), uint16(servicePort), u8proto.ANY, 0, 0)
	// use index 0 to indicate service item
	svcValue := NewService4Value(Backend4Key{0}, uint16(backendNumber))
	err = progs.connectObj.bpf_connectMaps.LB4SERVICES_MAP_V2.Update(svcKey.ToNetwork(), svcValue.ToNetwork(), ebpf.UpdateAny)
	if err != nil {
		panic(err)
	}

	podIp1 := "1.1.1.1"
	backendPort1 := 80
	backendID1 := 0
	slotIndex1 := 1
	backendKey1 := Backend4Key{uint32(backendID1)}
	backendServiceKey := NewService4Key(net.ParseIP(serviceIP), uint16(servicePort), u8proto.ANY, 0, uint16(slotIndex1))
	backendServiceValue := NewService4Value(backendKey1, 0)
	err = progs.connectObj.bpf_connectMaps.LB4SERVICES_MAP_V2.Update(backendServiceKey.ToNetwork(), backendServiceValue.ToNetwork(), ebpf.UpdateAny)
	if err != nil {
		panic(err)
	}
	backendValue, _ := NewBackend4Value(net.ParseIP(podIp1), uint16(backendPort1), u8proto.ANY, loadbalancer.BackendStateActive)
	err = progs.connectObj.bpf_connectMaps.LB4BACKEND_MAP_V2.Update(backendKey1, backendValue.ToNetwork(), ebpf.UpdateAny)
	if err != nil {
		panic(err)
	}

	// python3 -m http.server 8888
	podIp2 := "127.0.0.1"
	backendPort2 := 8888
	backendID2 := 1
	slotIndex2 := 2
	backendKey2 := Backend4Key{uint32(backendID2)}
	backendServiceKey2 := NewService4Key(net.ParseIP(serviceIP), uint16(servicePort), u8proto.ANY, 0, uint16(slotIndex2))
	backendServiceValue2 := NewService4Value(backendKey2, 0)
	err = progs.connectObj.bpf_connectMaps.LB4SERVICES_MAP_V2.Update(backendServiceKey2.ToNetwork(), backendServiceValue2.ToNetwork(), ebpf.UpdateAny)
	if err != nil {
		panic(err)
	}
	backendValue2, _ := NewBackend4Value(net.ParseIP(podIp2), uint16(backendPort2), u8proto.ANY, loadbalancer.BackendStateActive)
	err = progs.connectObj.bpf_connectMaps.LB4BACKEND_MAP_V2.Update(backendKey2, backendValue2.ToNetwork(), ebpf.UpdateAny)
	if err != nil {
		panic(err)
	}

	err = progs.Attach()
	if err != nil {
		fmt.Println("[ERROR] Attaching failed:", err)
	}
	defer progs.Close()

	time.Sleep(time.Minute)
	fmt.Println("[INFO] Time is up...")
}
