package monitor

import (
	"fmt"
	"os"
	"strconv"
	"time"

	"github.com/shirou/gopsutil/v3/host"
	"github.com/spf13/cobra"

	"github.com/linuxkerneltravel/lmp/eBPF_Supermarket/sidecar/k8s"
	"github.com/linuxkerneltravel/lmp/eBPF_Supermarket/sidecar/optimize/sockredir"
	"github.com/linuxkerneltravel/lmp/eBPF_Supermarket/sidecar/perf/net"
	"github.com/linuxkerneltravel/lmp/eBPF_Supermarket/sidecar/tools"
	"github.com/linuxkerneltravel/lmp/eBPF_Supermarket/sidecar/visualization"
)

var startedMinikubeStatus = `host: Running
kubelet: Running
apiserver: Running`

// Variables for all monitor sub-commands
// All available after `PreRun` procedure
var (
	// configs
	podName      string
	podLabel     string
	nameSpace    string
	kubeconfig   string
	exporterPort string
	jaegerAgent  string

	// control words
	forceMinikube bool
	withSockops   bool
	sidecarMode   string

	// intermediate variables
	nodeName string
)

func NewMonitorCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "monitor",
		Short:   "Starts monitor for sidecar",
		Long:    "",
		Example: "pmoas monitor all --pod sidecar-demo ",
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Println("\"pmoas monitor\" requires 1 argument.\nSee 'pmoas monitor --help'.")
			return nil
		},
	}

	addResetFlags(cmd)
	addCommand(cmd)
	return cmd
}

func addResetFlags(cmd *cobra.Command) {
	// Define flags and configuration settings.
	cmd.PersistentFlags().StringVar(&podName, "pod", "", "The pod to be monitored")
	cmd.PersistentFlags().StringVar(&podLabel, "pod-label", "", "The label of pod to be monitored")
	cmd.PersistentFlags().StringVar(&nameSpace, "namespace", "default", "The namespace of pod to be monitored")
	cmd.PersistentFlags().StringVar(&kubeconfig, "kubeconfig", "", "The kubeconfig of k8s cluster")

	cmd.PersistentFlags().StringVar(&exporterPort, "exporter-port", "8765", "The exporter port of this monitor")
	cmd.PersistentFlags().StringVar(&jaegerAgent, "jaeger-agent", "", "Jaeger agent endpoint")

	cmd.PersistentFlags().BoolVar(&forceMinikube, "force-minikube", false, "Ignore Minikube checks and force Minikube mode")
	cmd.PersistentFlags().BoolVar(&withSockops, "with-sockops", false, "Start monitor with sockops optimization")
	cmd.PersistentFlags().StringVar(&sidecarMode, "sidecar-mode", "blur", "Specify the kind of sidecar: envoy, demo, or blur for now")
}

func addCommand(cmd *cobra.Command) {
	cmd.AddCommand(NewMonitorAllCmd())
	cmd.AddCommand(NewMonitorSocketCmd())
	cmd.AddCommand(NewMonitorStackCmd())
}

// preRunMonitor performs pre-flight checks for all sub-commands
func preRunMonitor(cmd *cobra.Command, args []string) error {
	// Pre-flight check for k8s and node status
	checkedKubeconfig, checkedNodeName, _, _, err := k8s.PreflightCheck(kubeconfig)
	if err != nil {
		return err
	}
	kubeconfig = checkedKubeconfig
	nodeName = checkedNodeName

	// Detect Minikube mode
	if tools.IsInMinikubeMode() || forceMinikube {
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
	net.TimeOffset = net.TimeOffset.Add(-time.Duration(uptime * 1000000000))

	// start metrics exporter
	visualization.VisPort = exporterPort
	go visualization.StratExporter()

	if jaegerAgent == "" {
		if os.Getenv("VISUALIZE_IP") != "" {
			visualization.JaegerAgentHostPort = os.Getenv("VISUALIZE_IP") + ":" + "6831"
		} else {
			visualization.JaegerAgentHostPort = "127.0.0.1:6831"
		}
	} else {
		visualization.JaegerAgentHostPort = jaegerAgent
	}

	if podName == "" && podLabel != "" {
		podName, err = tools.GetPodNameFromNodeAndLabel(kubeconfig, nameSpace, nodeName, podLabel)
		if err != nil {
			return err
		}
	}

	return nil
}

func sockOpsRedirect() {
	if withSockops {
		localIP, _ := tools.IpToUint32("127.0.0.1")
		localIPEnvoy, _ := tools.IpToUint32("127.0.0.6")
		go sockredir.EnableSockOpsRedirect([]int{int(localIP), int(localIPEnvoy)})
	}
}
