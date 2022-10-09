package config

import (
	"os"

	"github.com/lmp/eBPF_Supermarket/eBPF_DDoS/pkg/ebpf"
)

var PluginMap = map[string]ebpf.Plugin{
	"dns": new(ebpf.DNSDefender),
}

var (
	Plugins   []string
	Interface = getEnvOrDefault("LMP_DDOS_INTERFACE", "eth0")
)

func getEnvOrDefault(name, defaultValue string) string {
	if value, ok := os.LookupEnv(name); ok {
		return value
	}
	return defaultValue
}
