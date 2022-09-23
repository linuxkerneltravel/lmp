package sockredir

import (
	"fmt"
	"os"
	"os/signal"

	"github.com/cilium/ebpf"

	"github.com/linuxkerneltravel/lmp/eBPF_Supermarket/sidecar/bpf/sockops"
)

func EnableSockOpsRedirect(ipList []int) {
	programs, err := sockops.LoadProgram()
	if err != nil {
		fmt.Println("[ERROR] Loading program failed:", err)
		return
	}

	// enable debug
	err = programs.SockopsObjs.DebugMap.Update(uint32(0), uint32(1), ebpf.UpdateAny)
	if err != nil {
		fmt.Println("[ERROR] update debug_map failed:", err)
	}

	// set local bind IP address
	for i := 0; i < len(ipList); i++ {
		err = programs.SockopsObjs.LocalIpMap.Update(uint32(ipList[i]), uint32(1), ebpf.UpdateAny)
		if err != nil {
			fmt.Println("[ERROR] update local_ip_map failed:", err)
		}
	}

	err = programs.Attach()
	if err != nil {
		fmt.Println("[ERROR] Attaching program failed:", err)
		programs.Close()
		return
	}
	defer programs.Close()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, os.Kill)
	<-sig
}
