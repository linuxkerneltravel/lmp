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
	"strconv"
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
	fmt.Println("[INFO] Exiting...")

	if p.connectCgroup != nil {
		fmt.Printf("[INFO] Closing connect cgroup...\n")
		p.connectCgroup.Close()
	}

	if p.connectObj.bpf_connectMaps.LB4SERVICES_MAP_V2 != nil {
		p.connectObj.bpf_connectMaps.LB4SERVICES_MAP_V2.Unpin()
		p.connectObj.bpf_connectMaps.LB4SERVICES_MAP_V2.Close()
		fmt.Println("[INFO] Unpin and close service map")
	}

	if p.connectObj.bpf_connectMaps.LB4BACKEND_MAP_V2 != nil {
		p.connectObj.bpf_connectMaps.LB4BACKEND_MAP_V2.Unpin()
		p.connectObj.bpf_connectMaps.LB4BACKEND_MAP_V2.Close()
		fmt.Println("[INFO] Unpin and close backend map")
	}

	err := os.Remove(MapsPinPath)
	if err != nil {
		fmt.Printf("[WARNING] remove map pin file path %s failed: %s\n", MapsPinPath, err)
	}
}

// InsertServiceItem inserts a service item into service map
func (p *Programs) InsertServiceItem(serviceIP string, servicePort string, backendNumber int) bool {
	servicePortInt, err := strconv.Atoi(servicePort)
	if err != nil {
		fmt.Println("[ERROR] InsertServiceItem: servicePort parse failed: ", err)
		return false
	}
	serviceKey := NewService4Key(net.ParseIP(serviceIP), uint16(servicePortInt), u8proto.ANY, 0, 0)
	// use index 0 to indicate service item, of course the possibility is zero, which is never be used
	serviceValue := NewService4Value(Backend4Key{0}, uint16(backendNumber), Possibility{0})
	err = p.connectObj.bpf_connectMaps.LB4SERVICES_MAP_V2.Update(serviceKey.ToNetwork(), serviceValue.ToNetwork(), ebpf.UpdateAny)
	if err != nil {
		fmt.Println("[ERROR] InsertServiceItem: connectObj.bpf_connectMaps.LB4SERVICES_MAP_V2.Update failed: ", err)
		return false
	}

	fmt.Printf("[INFO] InsertServiceItem succeeded: serviceIP: %s servicePort: %d backendNumber: %d\n", serviceIP, servicePortInt, backendNumber)
	return true
}

// DeleteServiceItem deletes an item of service map. Delete service itself when slotIndex = 0
func (p *Programs) DeleteServiceItem(serviceIP string, servicePort int, slotIndex int) bool {
	serviceKey := NewService4Key(net.ParseIP(serviceIP), uint16(servicePort), u8proto.ANY, 0, uint16(slotIndex))
	err := p.connectObj.bpf_connectMaps.LB4SERVICES_MAP_V2.Delete(serviceKey.ToNetwork())
	if err != nil {
		fmt.Println("[ERROR] DeleteServiceItem: connectObj.bpf_connectMaps.LB4SERVICES_MAP_V2.Delete failed: ", err)
		return false
	}
	fmt.Printf("[INFO] DeleteServiceItem succeeded: serviceIP: %s servicePort: %d slotIndex: %d\n", serviceIP, servicePort, slotIndex)
	return true
}

// InsertBackendItem inserts backend item into service map and backend map
func (p *Programs) InsertBackendItem(serviceIP string, servicePort int, backendIP string, backendPort int, backendID int, slotIndex int, possibility float64) bool {
	// Use allocated backendID to point to and store backend information
	backendKey := Backend4Key{uint32(backendID)}
	backendServiceKey := NewService4Key(net.ParseIP(serviceIP), uint16(servicePort), u8proto.ANY, 0, uint16(slotIndex))
	backendServiceValue := NewService4Value(backendKey, 0, Possibility{possibility})
	err := p.connectObj.bpf_connectMaps.LB4SERVICES_MAP_V2.Update(backendServiceKey.ToNetwork(), backendServiceValue.ToNetwork(), ebpf.UpdateAny)
	if err != nil {
		fmt.Println("[ERROR] InsertBackendItem: connectObj.bpf_connectMaps.LB4SERVICES_MAP_V2.Update failed:", err)
		return false
	}

	backendValue := NewBackend4Value(net.ParseIP(backendIP), uint16(backendPort), u8proto.ANY, loadbalancer.BackendStateActive)
	err = p.connectObj.bpf_connectMaps.LB4BACKEND_MAP_V2.Update(backendKey, backendValue.ToNetwork(), ebpf.UpdateAny)
	if err != nil {
		fmt.Println("[ERROR] InsertBackendItem: connectObj.bpf_connectMaps.LB4BACKEND_MAP_V2.Update failed:", err)
		return false
	}
	fmt.Printf("[INFO] InsertBackendItem succeeded: serviceIP: %s servicePort: %d backendID: %d slotIndex: %d possibility: %.2f\n", serviceIP, servicePort, backendID, slotIndex, possibility)
	return true
}

// DeleteBackendItem deletes an item specified by backendID in backend map
func (p *Programs) DeleteBackendItem(backendID int) bool {
	backendKey := Backend4Key{uint32(backendID)}
	err := p.connectObj.bpf_connectMaps.LB4BACKEND_MAP_V2.Delete(backendKey)
	if err != nil {
		fmt.Println("[ERROR] DeleteBackendItem: connectObj.bpf_connectMaps.LB4BACKEND_MAP_V2.Delete Delete:", err)
		return false
	}
	fmt.Printf("[INFO] DeleteBackendItem succeeded: backendID: %d\n", backendID)
	return true
}

// AutoInsertService inserts an organized service item into map
func (p *Programs) AutoInsertService(service Service, backendList []Backend) {
	p.InsertServiceItem(service.IP, service.Port, len(backendList))
	for i, backend := range backendList {
		p.AutoInsertBackend(service.IP, service.Port, backend.IP, backend.Port, i+1, backend.Possibility)
	}
}

// AutoDeleteService deletes an organized service item with backend items from map
func (p *Programs) AutoDeleteService(service Service) bool {
	serviceIP := service.IP
	servicePort, err := strconv.Atoi(service.Port)
	if err != nil {
		fmt.Println("[ERROR] AutoDeleteService: servicePort parse failed: ", err)
		return false
	}
	serviceKey := NewService4Key(net.ParseIP(serviceIP), uint16(servicePort), u8proto.ANY, 0, 0)
	serviceValue := NewService4Value(Backend4Key{0}, uint16(0), Possibility{0})
	err = p.connectObj.bpf_connectMaps.LB4SERVICES_MAP_V2.Lookup(serviceKey.ToNetwork(), serviceValue)
	if err != nil {
		fmt.Println("[ERROR] AutoDeleteService: connectObj.bpf_connectMaps.LB4SERVICES_MAP_V2.Lookup failed:", err)
		return false
	}
	fmt.Println("[DEBUG] To delete service", serviceKey.String())
	p.DeleteServiceItem(serviceIP, servicePort, 0)
	for i := 1; i <= int(serviceValue.Count); i++ {
		backendServiceKey := NewService4Key(net.ParseIP(serviceIP), uint16(servicePort), u8proto.ANY, 0, uint16(i))
		backendServiceValue := NewService4Value(Backend4Key{uint32(0)}, 0, Possibility{0})
		err := p.connectObj.bpf_connectMaps.LB4SERVICES_MAP_V2.Lookup(backendServiceKey.ToNetwork(), backendServiceValue)
		if err != nil {
			fmt.Println("[WARNING] AutoDeleteService: connectObj.bpf_connectMaps.LB4SERVICES_MAP_V2.Lookup failed:", err)
			break
		}
		fmt.Printf("[DEBUG] To delete backend backend service: backendServiceKey: %s, backendServiceValue: %s\n", backendServiceKey.String(), backendServiceValue.String())
		p.AutoDeleteBackend(int(backendServiceValue.BackendID.ID))
		p.DeleteServiceItem(serviceIP, servicePort, i)
	}
	fmt.Printf("[INFO] AutoDeleteService succeeded: serviceIP: %s servicePort: %d\n", serviceIP, servicePort)
	return true
}

// AutoInsertBackend inserts an organized backend item into map
func (p *Programs) AutoInsertBackend(serviceIP string, servicePortStr string, backendIP string, backendPortStr string, slotIndex int, possibility float64) bool {
	backendID := p.currentIndex
	p.currentIndex++
	servicePort, _ := strconv.Atoi(servicePortStr)
	backendPort, _ := strconv.Atoi(backendPortStr)
	ok := p.InsertBackendItem(serviceIP, servicePort, backendIP, backendPort, backendID, slotIndex, possibility)
	if ok {
		p.backEndSet[backendID] = true
		fmt.Printf("[INFO] AutoInsertBackend succeeded: serviceIP: %s, servicePort: %d, backendIP: %s, backendPort: %d, backendID: %d, slotIndex: %d, possibility: %.2f\n", serviceIP, servicePort, backendIP, backendPort, backendID, slotIndex, possibility)
	}
	return ok
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

type Service struct {
	IP   string
	Port string
}

type Backend struct {
	IP          string
	Port        string
	Possibility float64
}

func Sample() {
	progs, err := LoadProgram()
	if err != nil {
		fmt.Println("[ERROR] Loading program failed:", err)
		return
	}

	s := Service{
		IP:   "1.1.1.1",
		Port: "80", // TODO: 0 means it will not be modified
	}
	b := []Backend{
		{
			IP:          "1.1.1.1",
			Port:        "80",
			Possibility: 0.25,
		}, {
			IP:          "127.0.0.1",
			Port:        "8000",
			Possibility: 0.75,
		},
	}

	progs.AutoInsertService(s, b)

	// serviceIP := "1.1.1.1"
	// servicePort := "80"
	// backendPort1 := "80"
	// backendPort2 := "8888"
	// progs.InsertServiceItem(serviceIP, servicePort, 2)
	// progs.AutoInsertBackend(serviceIP, servicePort, "1.1.1.1", backendPort1, 1, 0.25)
	// progs.AutoInsertBackend(serviceIP, servicePort, "127.0.0.1", backendPort2, 2, 0.75)

	err = progs.Attach()
	if err != nil {
		fmt.Println("[ERROR] Attaching failed:", err)
	}
	defer progs.Close()

	time.Sleep(time.Minute)
	fmt.Println("[INFO] Time is up...")
	progs.AutoDeleteService(s)
	// c := make(chan os.Signal, 1)
	// signal.Notify(c)
	// <-c
}
