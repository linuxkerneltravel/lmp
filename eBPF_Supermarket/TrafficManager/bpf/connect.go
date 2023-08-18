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

func (p *Programs) DeleteServiceItem(serviceIP string, slot int) bool {
	serviceKey := NewService4Key(net.ParseIP(serviceIP), 0, u8proto.ANY, 0, uint16(slot))
	err := p.connectObj.bpf_connectMaps.LB4SERVICES_MAP_V2.Delete(serviceKey.ToNetwork())
	if err != nil {
		fmt.Println("[ERROR] DeleteServiceItem: connectObj.bpf_connectMaps.LB4SERVICES_MAP_V2.Delete failed: ", err)
		return false
	}
	return true
}

func (p *Programs) InsertServiceItem(serviceIP string, servicePort int, backendNumber int) {
	svcKey := NewService4Key(net.ParseIP(serviceIP), uint16(servicePort), u8proto.ANY, 0, 0)
	// use index 0 to indicate service item, of course the possibility is zero, which is never be used
	svcValue := NewService4Value(Backend4Key{0}, uint16(backendNumber), Possibility{0})
	err := p.connectObj.bpf_connectMaps.LB4SERVICES_MAP_V2.Update(svcKey.ToNetwork(), svcValue.ToNetwork(), ebpf.UpdateAny)
	if err != nil {
		fmt.Println("[ERROR] InsertServiceItem: connectObj.bpf_connectMaps.LB4SERVICES_MAP_V2.Update failed: ", err)
		return
	}
	fmt.Printf("[INFO] InsertServiceItem succeeded: serviceIP: %s servicePort: %d backendNumber: %d\n", serviceIP, servicePort, backendNumber)
}

func (p *Programs) DeleteBackendItem(backendID int) bool {
	backendKey := Backend4Key{uint32(backendID)}
	err := p.connectObj.bpf_connectMaps.LB4BACKEND_MAP_V2.Delete(backendKey)
	if err != nil {
		fmt.Println("[ERROR] DeleteBackendItem: connectObj.bpf_connectMaps.LB4BACKEND_MAP_V2.Delete Delete:", err)
		return false
	}
	return true
}

func (p *Programs) InsertBackendItem(serviceIP string, servicePort int, backendIP string, backendPort int, backendID int, slotIndex int, possibility float64) bool {
	backendKey := Backend4Key{uint32(backendID)}
	backendServiceKey := NewService4Key(net.ParseIP(serviceIP), uint16(servicePort), u8proto.ANY, 0, uint16(slotIndex))
	backendServiceValue := NewService4Value(backendKey, 0, Possibility{possibility})
	err := p.connectObj.bpf_connectMaps.LB4SERVICES_MAP_V2.Update(backendServiceKey.ToNetwork(), backendServiceValue.ToNetwork(), ebpf.UpdateAny)
	if err != nil {
		fmt.Println("[ERROR] InsertBackendItem: connectObj.bpf_connectMaps.LB4SERVICES_MAP_V2.Update failed:", err)
		return false
	}

	backendValue, _ := NewBackend4Value(net.ParseIP(backendIP), uint16(backendPort), u8proto.ANY, loadbalancer.BackendStateActive)
	err = p.connectObj.bpf_connectMaps.LB4BACKEND_MAP_V2.Update(backendKey, backendValue.ToNetwork(), ebpf.UpdateAny)
	if err != nil {
		fmt.Println("[ERROR] InsertBackendItem: connectObj.bpf_connectMaps.LB4BACKEND_MAP_V2.Update failed:", err)
		return false
	}

	fmt.Printf("[INFO] InsertBackendItem succeeded: serviceIP: %s servicePort: %d backendID: %d slotIndex: %d possibility: %.2f\n", serviceIP, servicePort, backendID, slotIndex, possibility)
	return true
}

// AutoInsertService inserts an organized service item into map
// TODO: implement it
func (p *Programs) AutoInsertService(serviceIP string, servicePort int, backendNumber int) {
	p.InsertServiceItem(serviceIP, servicePort, backendNumber)
}

// AutoDeleteService deletes an organized service item with backend items from map
func (p *Programs) AutoDeleteService(serviceIP string, servicePort int) bool {
	serviceKey := NewService4Key(net.ParseIP(serviceIP), uint16(servicePort), u8proto.ANY, 0, 0)
	serviceValue := NewService4Value(Backend4Key{0}, uint16(0), Possibility{0})
	err := p.connectObj.bpf_connectMaps.LB4SERVICES_MAP_V2.Lookup(serviceKey.ToNetwork(), serviceValue)
	if err != nil {
		fmt.Println("[ERROR] AutoDeleteService: connectObj.bpf_connectMaps.LB4SERVICES_MAP_V2.Lookup failed:", err)
		return false
	}
	fmt.Println("[DEBUG] To delete service", serviceValue)
	p.DeleteServiceItem(serviceIP, 0)
	for i := 0; i < int(serviceValue.Count); i++ {
		backendServiceKey := NewService4Key(net.ParseIP(serviceIP), 0, u8proto.ANY, 0, uint16(i+1))
		backendServiceValue := NewService4Value(Backend4Key{uint32(0)}, 0, Possibility{0})
		err := p.connectObj.bpf_connectMaps.LB4SERVICES_MAP_V2.Lookup(backendServiceKey.ToNetwork(), backendServiceValue)
		if err != nil {
			fmt.Println("[WARNING] AutoDeleteService: connectObj.bpf_connectMaps.LB4SERVICES_MAP_V2.Lookup failed:", err)
			break
		}
		fmt.Println("[DEBUG] To delete backend:", backendServiceValue)
		p.AutoDeleteBackend(int(backendServiceValue.BackendID.ID))
		p.DeleteServiceItem(serviceIP, i+1)
	}
	fmt.Printf("[INFO] AutoDeleteService succeeded: serviceIP: %s servicePort: %d\n", serviceIP, servicePort)
	return true
}

// AutoInsertBackend inserts an organized backend item into map
func (p *Programs) AutoInsertBackend(serviceIP string, servicePort int, backendIP string, backendPort int, slotIndex int, possibility float64) {
	backendID := p.currentIndex
	p.currentIndex++
	ok := p.InsertBackendItem(serviceIP, servicePort, backendIP, backendPort, backendID, slotIndex, possibility)
	if ok {
		p.backEndSet[backendID] = true
	}
}

// AutoDeleteBackend deletes an backend item from map
func (p *Programs) AutoDeleteBackend(backendID int) bool {
	delete(p.backEndSet, backendID)
	ok := p.DeleteBackendItem(backendID)
	if ok {
		fmt.Println("[INFO] AutoDeleteBackend succeeded: backendID:", backendID)
	}
	return ok
}

func Sample() {
	progs, err := LoadProgram()
	if err != nil {
		fmt.Println("[ERROR] Loading program failed:", err)
		return
	}

	// set service
	serviceIP := "1.1.1.1"
	servicePort := 80 // TODO: 0 means it will not be modified
	backendPort1 := 80
	backendPort2 := 8888
	progs.InsertServiceItem(serviceIP, servicePort, 2)
	progs.AutoInsertBackend(serviceIP, servicePort, "1.1.1.1", backendPort1, 1, 0.75)
	progs.AutoInsertBackend(serviceIP, servicePort, "127.0.0.1", backendPort2, 2, 0.25)

	err = progs.Attach()
	if err != nil {
		fmt.Println("[ERROR] Attaching failed:", err)
	}
	defer progs.Close()

	time.Sleep(time.Minute)
	fmt.Println("[INFO] Time is up...")
	progs.AutoDeleteService("1.1.1.1", servicePort)
	//c := make(chan os.Signal, 1)
	//signal.Notify(c)
	//<-c
}
