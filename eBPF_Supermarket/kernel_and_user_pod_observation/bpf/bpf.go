package bpf

import (
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"

	"github.com/iovisor/gobpf/bcc"
)

const TraceFs = "/sys/kernel/debug/tracing"

func TracepointExists(category string, event string) bool {
	eventDir := filepath.Join(TraceFs, "events", category, event)
	fileInfo, _ := os.Stat(eventDir)
	return fileInfo.IsDir()
}

func GetProtocolFromInt(p int) string {
	IpProto := map[int]string{
		1:  "ICMP",
		6:  "TCP",
		17: "UDP",
	}
	value, ok := IpProto[p]
	if ok {
		return value
	} else {
		return "UNKNOWN"
	}
}

// GetTcpFlags gets TCP flags from combined field
func GetTcpFlags(f int, reversed bool) string {
	tcpFlags := []string{"FIN", "SYN", "RST", "PSH", "ACK", "URG", "ECE", "CWR"}
	if reversed {
		tcpFlags = []string{"CWR", "ECE", "URG", "ACK", "PSH", "RST", "SYN", "FIN"}
	}
	res := ""
	multiFlag := false
	for i := 0; i < len(tcpFlags); i++ {
		if (f & (1 << i)) != 0 {
			if multiFlag {
				res += ","
			}
			res += tcpFlags[i]
			multiFlag = true
		}
	}

	return res
}

// GetValueFromMap gets value from table
// for usage record only
func GetValueFromMap(m bcc.Table, key uint32) {
	id := make([]byte, 4)
	binary.LittleEndian.PutUint32(id, key)
	fmt.Println("id: ", id)
	res, err := m.Get(id)
	if err != nil {
		fmt.Println("get key failed")
	} else {
		fmt.Println(res)
	}

}
