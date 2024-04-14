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

func NewMonitorAllCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "all",
		Short:   "Monitor pod by all provided kernel tools.",
		Long:    "",
		Example: "kupod monitor kernel all --pod sidecar-demo",
		PreRunE: PreRunMonitorKernel,
		RunE:    MonitorKernelAll,
	}

	return cmd
}

func MonitorKernelAll(cmd *cobra.Command, args []string) error {
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
	var portList = []int{15006, 9080, 80, 8000}

	go kernel.GetRequestOverSidecarEvent(sidecarPid, servicePid, portList, data.PodName)

	for i := 0; i < len(sidecarProcesses); i++ {
		sidecarPid = append(sidecarPid, int(sidecarProcesses[i].Pid))
	}
	for i := 0; i < len(serviceProcesses); i++ {
		servicePid = append(servicePid, int(serviceProcesses[i].Pid))
	}
	var pidList []int
	pidList = append(pidList, sidecarPid...)
	pidList = append(pidList, servicePid...)

	targetPod, err := tools.LocateTargetPod(tools.GetDefaultKubeConfig(), data.PodName, data.NameSpace)

	so := kernel.SidecarOpt{
		SidecarPort: 8000,
		ServicePort: 80,
		LocalIP:     "127.0.0.1", // for Envoy, 127.0.0.6
		PodIp:       targetPod.Status.PodIP,
		NodeIp:      targetPod.Status.HostIP,
	}

	go kernel.GetKernelNetworkEvent(pidList, so, data.PodName)
	if data.VEthName != "" {
		go kernel.GetNicThroughputMetric(data.VEthName)
	}

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, os.Kill)
	<-sig

	return nil
}
