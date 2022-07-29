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
