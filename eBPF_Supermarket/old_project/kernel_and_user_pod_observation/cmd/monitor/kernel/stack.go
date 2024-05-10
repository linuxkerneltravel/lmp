package kernel

import (
	"fmt"
	"os"
	"os/signal"

	"github.com/spf13/cobra"

	"github.com/linuxkerneltravel/lmp/eBPF_Supermarket/sidecar/tools"

	"github.com/linuxkerneltravel/lmp/eBPF_Supermarket/kernel_and_user_pod_observation/data"
	"github.com/linuxkerneltravel/lmp/eBPF_Supermarket/kernel_and_user_pod_observation/k8s"
	"github.com/linuxkerneltravel/lmp/eBPF_Supermarket/kernel_and_user_pod_observation/perf/kernel"
)

func NewMonitorStackCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "stack",
		Short:   "Monitor pod by network stack probes.",
		Long:    "",
		Example: "pmoas monitor kernel stack --pod sidecar-demo",
		PreRunE: PreRunMonitorKernel,
		RunE:    MonitorKernelStack,
	}

	return cmd
}

func MonitorKernelStack(cmd *cobra.Command, args []string) error {
	SockOpsRedirect()

	sidecarProcesses, serviceProcesses, err := k8s.GetSidecarAndServiceProcess(data.Kubeconfig, data.NodeName, data.NameSpace, data.PodName)
	if err != nil {
		fmt.Printf("[ERROR] Got err: %s\n", err)
		os.Exit(1)
	}
	fmt.Printf("[FINISHED] Get sidecar processes '%s'\n", sidecarProcesses)
	fmt.Printf("[FINISHED] Get service processes '%s'\n", serviceProcesses)

	var sidecarPid []int
	var servicePid []int
	var pidList []int

	for i := 0; i < len(sidecarProcesses); i++ {
		sidecarPid = append(sidecarPid, int(sidecarProcesses[i].Pid))
	}
	for i := 0; i < len(serviceProcesses); i++ {
		servicePid = append(servicePid, int(serviceProcesses[i].Pid))
	}

	pidList = append(pidList, sidecarPid...)
	pidList = append(pidList, servicePid...)

	targetPod, err := tools.LocateTargetPod(data.Kubeconfig, data.PodName, data.NameSpace)

	so := kernel.SidecarOpt{
		SidecarPort: 8000,
		ServicePort: 80,
		LocalIP:     "127.0.0.1", // for Envoy, 127.0.0.6
		PodIp:       targetPod.Status.PodIP,
		NodeIp:      targetPod.Status.HostIP,
	}

	go kernel.GetKernelNetworkEvent(pidList, so, data.PodName)

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, os.Kill)
	<-sig

	return nil
}
