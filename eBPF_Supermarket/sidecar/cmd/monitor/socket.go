package monitor

import (
	"fmt"
	"os"
	"os/signal"

	"github.com/spf13/cobra"

	"github.com/linuxkerneltravel/lmp/eBPF_Supermarket/sidecar/k8s"
	"github.com/linuxkerneltravel/lmp/eBPF_Supermarket/sidecar/perf/net"
)

func NewMonitorSocketCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "socket",
		Short:   "Monitor sidecar by socket probes.",
		Long:    "",
		Example: "pmoas monitor socket --pod sidecar-demo",
		PreRunE: preRunMonitor,
		RunE: func(cmd *cobra.Command, args []string) error {
			sockOpsRedirect()

			sidecarProcesses, serviceProcesses, err := k8s.GetSidecarAndServiceProcess(kubeconfig, nodeName, nameSpace, podName)
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

			go net.GetRequestOverSidecarEvent(sidecarPid, servicePid, portList, podName)

			sig := make(chan os.Signal, 1)
			signal.Notify(sig, os.Interrupt, os.Kill)
			<-sig

			return nil
		},
	}

	return cmd
}
