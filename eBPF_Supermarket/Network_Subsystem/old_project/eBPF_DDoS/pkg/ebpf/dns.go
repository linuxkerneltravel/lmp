package ebpf

import (
	"github.com/lmp/eBPF_Supermarket/eBPF_DDoS/pkg/util"
)

type DNSDefender struct{}

func (d *DNSDefender) GetProgramIndex() uint32 {
	return 1
}

func (d *DNSDefender) Load() error {
	// create bpf maps
	if err := util.ExecCommand(`bpftool map create /sys/fs/bpf/xdp/globals/configuration \
type hash key 1 value 4 entries 255 name configuration && \
bpftool map create /sys/fs/bpf/xdp/globals/counter type lru_hash key 4 value 16 entries 65535 name counter`); err != nil {
		return err
	}
	// load xdp prog
	if err := util.ExecCommand(`cd bpf/dns-ddos/src && make xdp_dns_kern && \
bpftool -m prog load xdp_dns_kern.o /sys/fs/bpf/xdp_dns map name ddos_programs \
pinned /sys/fs/bpf/xdp/globals/ddos_programs \
map name configuration pinned /sys/fs/bpf/xdp/globals/configuration \
map name counter pinned /sys/fs/bpf/xdp/globals/counter`); err != nil {
		return err
	}
	// update bpf prog array
	return util.ExecCommand("bpftool map update pinned /sys/fs/bpf/xdp/globals/ddos_programs key 1 0 0 0 value pinned /sys/fs/bpf/xdp_dns")
}

func (d *DNSDefender) Run() error {
	// run user space prog
	return util.ExecCommand("python3 -u bpf/dns-ddos/src/catch_dns.py &")
}

func (d *DNSDefender) Unload() error {
	// clean up
	return util.ExecCommand("rm -f /sys/fs/bpf/xdp/globals/configuration && rm -f /sys/fs/bpf/xdp/globals/counter && rm -f /sys/fs/bpf/xdp_dns")
}
