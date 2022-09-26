package sockops

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -target bpf -cflags "-D__TARGET_ARCH_x86" bpf_redir   bpf_redir.c -- -I../headers
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -target bpf -cflags "-D__TARGET_ARCH_x86" bpf_sockops bpf_sockops.c -- -I../headers

import (
	"fmt"
	"os"
	"os/signal"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"

	"github.com/linuxkerneltravel/lmp/eBPF_Supermarket/sidecar/tools"
)

const MapsPinPath = "/sys/fs/bpf/sock_ops_map"

type Programs struct {
	SockopsObjs   bpf_sockopsObjects
	RedirObjs     bpf_redirObjects
	SockopsCgroup link.Link
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

	err = loadBpf_redirObjects(&programs.RedirObjs, &options)
	if err != nil {
		return Programs{}, fmt.Errorf("error load objects: %s\n", err)
	}

	err = loadBpf_sockopsObjects(&programs.SockopsObjs, &options)
	if err != nil {
		return Programs{}, fmt.Errorf("error load objects: %s\n", err)
	}

	return programs, err
}

func (p Programs) Attach() error {
	fmt.Println("Socket redirect started!")

	err := link.RawAttachProgram(link.RawAttachProgramOptions{
		Target:  p.RedirObjs.bpf_redirMaps.MapRedir.FD(),
		Program: p.RedirObjs.bpf_redirPrograms.BpfRedirProxy,
		Attach:  ebpf.AttachSkMsgVerdict,
	})
	if err != nil {
		return fmt.Errorf("error attaching to sockmap: %s", err)
	}

	cgroupPath, err := tools.DetectCgroupPath()
	if err != nil {
		return fmt.Errorf("detect cgroup path failed: %s", err)
	}
	p.SockopsCgroup, err = link.AttachCgroup(link.CgroupOptions{
		Path:    cgroupPath,
		Attach:  ebpf.AttachCGroupSockOps,
		Program: p.SockopsObjs.bpf_sockopsPrograms.BpfSockmap,
	})
	if err != nil {
		return fmt.Errorf("error attaching sockredir to cgroup: %s", err)
	}

	return nil
}

func (p Programs) Close() {
	fmt.Println("Exiting...")
	var err error

	if p.SockopsCgroup != nil {
		fmt.Printf("Closing sockredir cgroup...\n")
		p.SockopsCgroup.Close()
	}

	if p.RedirObjs.bpf_redirPrograms.BpfRedirProxy != nil {
		err = link.RawDetachProgram(link.RawDetachProgramOptions{
			Target:  p.RedirObjs.bpf_redirMaps.MapRedir.FD(),
			Program: p.RedirObjs.bpf_redirPrograms.BpfRedirProxy,
			Attach:  ebpf.AttachSkMsgVerdict,
		})
		if err != nil {
			fmt.Printf("Error detaching '%s'\n", err)
		}

		fmt.Printf("Closing redirect prog...\n")
	}

	if p.SockopsObjs.bpf_sockopsMaps.MapActiveEstab != nil {
		p.SockopsObjs.bpf_sockopsMaps.MapActiveEstab.Unpin()
		p.SockopsObjs.bpf_sockopsMaps.MapActiveEstab.Close()
	}

	if p.SockopsObjs.bpf_sockopsMaps.MapProxy != nil {
		p.SockopsObjs.bpf_sockopsMaps.MapProxy.Unpin()
		p.SockopsObjs.bpf_sockopsMaps.MapProxy.Close()
	}

	if p.SockopsObjs.bpf_sockopsMaps.MapRedir != nil {
		p.SockopsObjs.bpf_sockopsMaps.MapRedir.Unpin()
		p.SockopsObjs.bpf_sockopsMaps.MapRedir.Close()
	}

	if p.SockopsObjs.bpf_sockopsMaps.DebugMap != nil {
		p.SockopsObjs.bpf_sockopsMaps.DebugMap.Unpin()
		p.SockopsObjs.bpf_sockopsMaps.DebugMap.Close()
	}

	if p.SockopsObjs.bpf_sockopsMaps.LocalIpMap != nil {
		p.SockopsObjs.bpf_sockopsMaps.LocalIpMap.Unpin()
		p.SockopsObjs.bpf_sockopsMaps.LocalIpMap.Close()
	}
}

func Sample() {
	progs, err := LoadProgram()
	if err != nil {
		fmt.Println("[ERROR] Loading program failed:", err)
		return
	}

	// enable debug
	err = progs.SockopsObjs.DebugMap.Update(uint32(0), uint32(1), ebpf.UpdateAny)
	if err != nil {
		fmt.Println("[ERROR] update debug_map failed:", err)
	}

	// set local bind IP address
	err = progs.SockopsObjs.LocalIpMap.Update(uint32(0x100007f), uint32(1), ebpf.UpdateAny)
	err = progs.SockopsObjs.LocalIpMap.Update(uint32(0x600007f), uint32(1), ebpf.UpdateAny)
	if err != nil {
		fmt.Println("[ERROR] update local_ip_map failed:", err)
	}

	err = progs.Attach()
	if err != nil {
		fmt.Println("[ERROR] Attaching failed:", err)
	}
	defer progs.Close()

	c := make(chan os.Signal, 1)
	signal.Notify(c)
	<-c
}
