package tools

import (
	"encoding/binary"
	"fmt"
	"net"
)

type uint128 struct {
	Hi uint64
	Lo uint64
}

type Ipv4Address uint32

type Ipv6Address uint128

type UnifiedAddress struct {
	Hi uint64
	Lo uint64
}

type Mac struct {
	Data [6]uint8
}

func (ip Ipv4Address) ToString() string {
	return fmt.Sprintf("%d.%d.%d.%d", byte(ip), byte(ip>>8), byte(ip>>16), byte(ip>>24))
}

func (ip Ipv6Address) ToString() string {
	a := make([]byte, 8)
	b := make([]byte, 8)
	binary.LittleEndian.PutUint64(a, ip.Hi)
	binary.LittleEndian.PutUint64(b, ip.Lo)

	b = append(b, a...)
	v := net.IP(b)
	return v.String()
}

// ToString converts binary UnifiedAddress by provided IP version
func (ip UnifiedAddress) ToString(version int) string {
	if version == 4 {
		return Ipv4Address(ip.Hi).ToString()
	} else if version == 6 {
		var v6Add Ipv6Address
		v6Add.Lo = ip.Lo
		v6Add.Hi = ip.Hi
		return v6Add.ToString()
	}
	return ""
}

// IpToUint32 converts IP in string (e.g. 127.0.0.1) to int (e.g. 0x100007f)
func IpToUint32(ipAddr string) (uint32, error) {
	ip := net.ParseIP(ipAddr)
	if ip == nil {
		return 0, fmt.Errorf("wrong IP address format")
	}
	ip = ip.To4()
	return binary.LittleEndian.Uint32(ip), nil
}

func (m Mac) ToString() string {
	res := ""
	for i := 0; i < 6; i++ {
		res += fmt.Sprintf("%02x", m.Data[i])
		if i != 5 {
			res += ":"
		}
	}
	return res
}

// NetToHostShort converts a 16-bit integer from network to host byte order, aka "ntohs"
func NetToHostShort(i uint16) uint16 {
	data := make([]byte, 2)
	binary.BigEndian.PutUint16(data, i)
	return binary.LittleEndian.Uint16(data)
}

// NetToHostLong converts a 32-bit integer from network to host byte order, aka "ntohl"
func NetToHostLong(i uint32) uint32 {
	data := make([]byte, 4)
	binary.BigEndian.PutUint32(data, i)
	return binary.LittleEndian.Uint32(data)
}

// HostToNetShort converts a 16-bit integer from host to network byte order, aka "htons"
func HostToNetShort(i uint16) uint16 {
	b := make([]byte, 2)
	binary.LittleEndian.PutUint16(b, i)
	return binary.BigEndian.Uint16(b)
}

// HostToNetLong converts a 32-bit integer from host to network byte order, aka "htonl"
func HostToNetLong(i uint32) uint32 {
	b := make([]byte, 4)
	binary.LittleEndian.PutUint32(b, i)
	return binary.BigEndian.Uint32(b)
}
