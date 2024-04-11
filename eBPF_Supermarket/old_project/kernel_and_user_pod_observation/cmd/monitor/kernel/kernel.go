package kernel

import (
	"fmt"
	"os"
	"strconv"
	"time"

	"github.com/shirou/gopsutil/v3/host"
	"github.com/spf13/cobra"

	"github.com/linuxkerneltravel/lmp/eBPF_Supermarket/sidecar/optimize/sockredir"
	"github.com/linuxkerneltravel/lmp/eBPF_Supermarket/sidecar/tools"
	"github.com/linuxkerneltravel/lmp/eBPF_Supermarket/sidecar/visualization"

	"github.com/linuxkerneltravel/lmp/eBPF_Supermarket/kernel_and_user_pod_observation/data"
	"github.com/linuxkerneltravel/lmp/eBPF_Supermarket/kernel_and_user_pod_observation/k8s"
	"github.com/linuxkerneltravel/lmp/eBPF_Supermarket/kernel_and_user_pod_observation/perf/kernel"
)

func NewMonitorKernelCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "kernel",
		Short:   "Starts monitor for pod.",
		Long:    "",
		Example: "kupod monitor kernel all --pod sidecar-demo ",
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Println("\"kupod monitor kernel\" requires 1 argument.\nSee 'kupod monitor kernel --help'.")
			return nil
		},
	}

	addResetFlags(cmd)
	addCommand(cmd)
	return cmd
}

func addResetFlags(cmd *cobra.Command) {
	// Define flags and configuration settings.

}

func addCommand(cmd *cobra.Command) {
	cmd.AddCommand(NewMonitorAllCmd())
	cmd.AddCommand(NewMonitorSocketCmd())
	cmd.AddCommand(NewMonitorStackCmd())
}

// PreRunMonitorKernel performs pre-flight checks for all sub-commands
func PreRunMonitorKernel(cmd *cobra.Command, args []string) error {
	// Pre-flight check for k8s and node status
	checkedKubeconfig, checkedNodeName, _, _, err := k8s.PreflightCheck(data.Kubeconfig)
	if err != nil {
		return err
	}
	data.Kubeconfig = checkedKubeconfig
	data.NodeName = checkedNodeName

	// Detect Minikube mode
	if tools.IsInMinikubeMode() || data.ForceMinikube {
		minikubePid := os.Getenv("MINIKUBE_ROOT_PID")
		minikubePidInt, err := strconv.Atoi(minikubePid)
		if err != nil {
			return fmt.Errorf("MINIKUBE_ROOT_PID load failed: %s", minikubePid)
		}
		fmt.Println("[INFO] Minikube root pid:", minikubePidInt)
		tools.MinikubePid = minikubePidInt
	}

	// set up uptime offset
	uptime, err := host.Uptime()
	if err != nil {
		return err
	}
	kernel.TimeOffset = kernel.TimeOffset.Add(-time.Duration(uptime * 1000000000))

	// start metrics exporter
	visualization.VisPort = data.ExporterPort
	go visualization.StratExporter()

	if data.JaegerAgent == "" {
		if os.Getenv("VISUALIZE_IP") != "" {
			visualization.JaegerAgentHostPort = os.Getenv("VISUALIZE_IP") + ":" + "6831"
		} else {
			visualization.JaegerAgentHostPort = "127.0.0.1:6831"
		}
	} else {
		visualization.JaegerAgentHostPort = data.JaegerAgent
	}

	if data.PodName == "" && data.PodLabel != "" {
		data.PodName, err = tools.GetPodNameFromNodeAndLabel(data.Kubeconfig, data.NameSpace, data.NodeName, data.PodLabel)
		if err != nil {
			return err
		}
	}

	return nil
}

func SockOpsRedirect() {
	if data.WithSockops {
		localIP, _ := tools.IpToUint32("127.0.0.1")
		localIPEnvoy, _ := tools.IpToUint32("127.0.0.6")
		go sockredir.EnableSockOpsRedirect([]int{int(localIP), int(localIPEnvoy)})
	}
}
