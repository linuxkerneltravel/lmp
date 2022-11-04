package kernel

import (
	"fmt"
	"os"
	"os/signal"

	"github.com/spf13/cobra"

	"github.com/linuxkerneltravel/lmp/eBPF_Supermarket/kernel_and_user_pod_observation/data"
	"github.com/linuxkerneltravel/lmp/eBPF_Supermarket/kernel_and_user_pod_observation/k8s"
	"github.com/linuxkerneltravel/lmp/eBPF_Supermarket/kernel_and_user_pod_observation/perf/kernel"
)

func NewMonitorSocketCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "socket",
		Short:   "Monitor pod by socket probes.",
		Long:    "",
		Example: "pmoas monitor kernel socket --pod sidecar-demo",
		PreRunE: PreRunMonitorKernel,
		RunE:    MonitorKernelSocket,
	}

	return cmd
}

func MonitorKernelSocket(cmd *cobra.Command, args []string) error {
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

	for i := 0; i < len(sidecarProcesses); i++ {
		sidecarPid = append(sidecarPid, int(sidecarProcesses[i].Pid))
	}
	for i := 0; i < len(serviceProcesses); i++ {
		servicePid = append(servicePid, int(serviceProcesses[i].Pid))
	}

	go kernel.GetRequestOverSidecarEvent(sidecarPid, servicePid, portList, data.PodName)

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, os.Kill)
	<-sig

	return nil
}
