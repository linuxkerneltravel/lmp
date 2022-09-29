package monitor

import (
	"fmt"

	"github.com/linuxkerneltravel/lmp/eBPF_Supermarket/kernel_and_user_pod_observation/data"
	"github.com/spf13/cobra"

	"github.com/linuxkerneltravel/lmp/eBPF_Supermarket/kernel_and_user_pod_observation/cmd/monitor/kernel"
	"github.com/linuxkerneltravel/lmp/eBPF_Supermarket/kernel_and_user_pod_observation/cmd/monitor/user"
)

func NewMonitorCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "monitor",
		Short:   "Starts monitor for sidecar",
		Long:    "",
		Example: "kupod monitor all --pod sidecar-demo ",
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Println("\"kupod monitor\" requires 1 argument.\nSee 'kupod monitor --help'.")
			return nil
		},
	}

	addResetFlags(cmd)
	addCommand(cmd)
	return cmd
}

func addResetFlags(cmd *cobra.Command) {
	// Define flags and configuration settings.
	cmd.PersistentFlags().StringVar(&data.PodName, "pod", "", "The pod to be monitored")
	cmd.PersistentFlags().StringVar(&data.PodLabel, "pod-label", "", "The label of pod to be monitored")
	cmd.PersistentFlags().StringVar(&data.NameSpace, "namespace", "default", "The namespace of pod to be monitored")
	cmd.PersistentFlags().StringVar(&data.Kubeconfig, "kubeconfig", "", "The kubeconfig of k8s cluster")
	cmd.PersistentFlags().StringVar(&data.VEthName, "veth", "", "The VETH name of pod to be monitored")

	cmd.PersistentFlags().StringVar(&data.ExporterPort, "exporter-port", "8765", "The exporter port of this monitor")
	cmd.PersistentFlags().StringVar(&data.JaegerAgent, "jaeger-agent", "", "Jaeger agent endpoint")

	cmd.PersistentFlags().BoolVar(&data.ForceMinikube, "force-minikube", false, "Ignore Minikube checks and force Minikube mode")
	cmd.PersistentFlags().BoolVar(&data.WithSockops, "with-sockops", false, "Start monitor with sockops optimization")
	cmd.PersistentFlags().StringVar(&data.SidecarMode, "sidecar-mode", "blur", "Specify the kind of sidecar: envoy, demo, or blur for now")
}

func addCommand(cmd *cobra.Command) {
	cmd.AddCommand(NewMonitorAllCmd())
	cmd.AddCommand(kernel.NewMonitorKernelCmd())
	cmd.AddCommand(user.NewMonitorUserCmd())
}
