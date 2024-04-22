package monitor

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/linuxkerneltravel/lmp/eBPF_Supermarket/kernel_and_user_pod_observation/cmd/monitor/kernel"
	"github.com/linuxkerneltravel/lmp/eBPF_Supermarket/kernel_and_user_pod_observation/cmd/monitor/user"
	"github.com/linuxkerneltravel/lmp/eBPF_Supermarket/kernel_and_user_pod_observation/data"
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
	cmd.PersistentFlags().StringVar(&data.NameSpace, "namespace", "default", "The namespace of pod to be monitored")

	cmd.PersistentFlags().StringVar(&data.PodLabel, "pod-label", "", "The label of pod to be monitored")
	cmd.PersistentFlags().StringVar(&data.Kubeconfig, "kubeconfig", "", "The kubeconfig of k8s cluster")

	cmd.PersistentFlags().StringVar(&data.VEthName, "veth", "", "The VETH name of pod to be monitored")

	cmd.PersistentFlags().StringVar(&data.ExporterPort, "exporter-port", "8765", "The exporter port of this monitor")
	cmd.PersistentFlags().StringVar(&data.JaegerAgent, "jaeger-agent", "", "Jaeger agent endpoint")

	cmd.PersistentFlags().BoolVar(&data.ForceMinikube, "force-minikube", false, "Ignore Minikube checks and force Minikube mode")
	cmd.PersistentFlags().BoolVar(&data.WithSockops, "with-sockops", false, "Start monitor with sockops optimization")

	//for user mode
	cmd.PersistentFlags().StringVar(&data.ImageName, "imagename", "wyuei/http_server:v2.0", "The docker in Pod to be monitored with which image")
	cmd.PersistentFlags().StringVar(&data.GrpcPodName, "grpcpod", "grpcserver", "The pod to be monitored for grpc")
	cmd.PersistentFlags().StringVar(&data.GrpcImageName, "grpcimagename", "wyuei/grpc_server:latest", "The docker in Pod to be monitored with which image for grpc")
	cmd.PersistentFlags().StringVar(&data.PrometheusIP, "prometheus", "10.10.103.122:9091", "where the prometheus and push-gateway running on")
	cmd.PersistentFlags().StringVar(&data.NodeName, "nodename", "k8s-node2", "The node where the pods running on")
}

func addCommand(cmd *cobra.Command) {
	cmd.AddCommand(NewMonitorAllCmd())
	cmd.AddCommand(kernel.NewMonitorKernelCmd())
	cmd.AddCommand(user.NewMonitorUserCmd())
}
