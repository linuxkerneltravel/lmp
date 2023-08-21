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

import (
	"fmt"
	"net"

	"github.com/cilium/cilium/pkg/byteorder"
	"github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/types"
	"github.com/cilium/cilium/pkg/u8proto"
)

const maxPossibilityUnit = 2048

type pad2uint8 [2]uint8

type Service4Key struct {
	Address     types.IPv4 `align:"address"`
	Port        uint16     `align:"dport"`
	BackendSlot uint16     `align:"backend_slot"`
	Proto       uint8      `align:"proto"`
	Scope       uint8      `align:"scope"`
	Pad         pad2uint8  `align:"pad"`
}

func NewService4Key(ip net.IP, port uint16, proto u8proto.U8proto, scope uint8, slot uint16) *Service4Key { //
	key := Service4Key{
		Port:        port,
		Proto:       uint8(proto),
		Scope:       scope,
		BackendSlot: slot,
	}

	copy(key.Address[:], ip.To4())

	return &key
}

func (k *Service4Key) ToNetwork() *Service4Key {
	n := *k
	n.Port = byteorder.HostToNetwork16(n.Port)
	return &n
}

// ToHost converts Service4Key to host byte order.
func (k *Service4Key) ToHost() *Service4Key {
	h := *k
	h.Port = byteorder.NetworkToHost16(h.Port)
	return &h
}

func (k *Service4Key) String() string {
	kHost := k // .ToHost()
	addr := net.JoinHostPort(kHost.Address.String(), fmt.Sprintf("%d", kHost.Port))
	if kHost.Scope == loadbalancer.ScopeInternal {
		addr += "/i"
	}
	return addr
}

type Service4Value struct {
	BackendID   Backend4Key `align:"backend_id"`
	Count       uint16      `align:"count"`
	Possibility uint16      `align:"possibility"`
	Flags       uint8       `align:"flags"`
	Flags2      uint8       `align:"flags2"`
	Pad         pad2uint8   `align:"pad"`
}

func NewService4Value(backendId Backend4Key, count uint16, possibility Possibility) *Service4Value {
	value := Service4Value{
		BackendID:   backendId,
		Count:       count,
		Possibility: uint16(possibility.percentage * maxPossibilityUnit),
	}

	return &value
}

func (s *Service4Value) String() string {
	sHost := s.ToHost()
	return fmt.Sprintf("%d %d (%d) [0x%x 0x%x]", sHost.BackendID, sHost.Count, sHost.Possibility, sHost.Flags, sHost.Flags2)
}

func (s *Service4Value) ToNetwork() *Service4Value {
	n := *s
	// TODO: need more test
	// n.Possibility = byteorder.HostToNetwork16(n.Possibility)
	return &n
}

// ToHost converts Service4Value to host byte order.
func (s *Service4Value) ToHost() *Service4Value {
	h := *s
	// TODO: need more test
	// h.Possibility = byteorder.NetworkToHost16(h.Possibility)
	return &h
}

type Backend4Key struct {
	ID uint32
}

type Backend4Value struct {
	Address types.IPv4      `align:"address"`
	Port    uint16          `align:"port"`
	Proto   u8proto.U8proto `align:"proto"`
	Flags   uint8           `align:"flags"`
}

func NewBackend4Value(ip net.IP, port uint16, proto u8proto.U8proto, state loadbalancer.BackendState) (*Backend4Value, error) {
	ip4 := ip.To4()
	if ip4 == nil {
		return nil, fmt.Errorf("not an IPv4 address")
	}
	flags := loadbalancer.NewBackendFlags(state)

	val := Backend4Value{
		Port:  port,
		Proto: proto,
		Flags: flags,
	}
	copy(val.Address[:], ip.To4())

	return &val, nil
}

func (v *Backend4Value) ToNetwork() *Backend4Value {
	n := *v
	n.Port = byteorder.HostToNetwork16(n.Port)
	return &n
}

type Possibility struct {
	percentage float64
}

// func tes() {
//	IP := net.ParseIP("1.1.1.1")
//	var Port uint16 = 8080
//
//	svcKey := NewService4Key(IP, Port, u8proto.ANY, 0, 0)
// }
