package monitor

import (
	"fmt"
	"os"
	"os/signal"

	"github.com/spf13/cobra"

	"github.com/linuxkerneltravel/lmp/eBPF_Supermarket/kernel_and_user_pod_observation/cmd/monitor/kernel"
	"github.com/linuxkerneltravel/lmp/eBPF_Supermarket/kernel_and_user_pod_observation/cmd/monitor/user"
)

func NewMonitorAllCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "all",
		Short:   "Starts monitor for pod",
		Long:    "",
		Example: "kupod monitor all --pod sidecar-demo ",
		RunE:    DoMonitorAll,
	}

	addMonitorAllCommand(cmd)

	return cmd
}

func addMonitorAllCommand(cmd *cobra.Command) {

}

func DoMonitorAll(cmd *cobra.Command, args []string) error {
	go func() {
		err := kernel.MonitorKernelAll(cmd, args)
		if err != nil {
			fmt.Printf("[ERROR] in MonitorKernelAll: %s\n", err)
			os.Exit(1)
		}
	}()

	go func() {
		err := user.MonitorUserAll(cmd, args)
		if err != nil {
			fmt.Printf("[ERROR] in MonitorUserAll: %s\n", err)
			os.Exit(1)
		}
	}()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, os.Kill)
	<-sig

	return nil
}
