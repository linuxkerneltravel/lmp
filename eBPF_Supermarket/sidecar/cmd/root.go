package cmd

import (
	"github.com/spf13/cobra"

	"github.com/linuxkerneltravel/lmp/eBPF_Supermarket/sidecar/cmd/monitor"
)

var rootCmd = &cobra.Command{
	Use:   "pmoas",
	Short: "PMOAS is an eBPF-based tool for comprehensive monitoring and visualization of pods with sidecar",
	Long: `An eBPF-based efficient and powerful monitoring and visualization project for network 
event capture, flow of data packets in the pod's internal network protocol stack, 
container resource consumption acquisition in pod and so on, with visualization on the 
industry's common used visualization platforms.`,
}

func Execute(version string) error {
	currentVersion = version
	if err := rootCmd.Execute(); err != nil {
		return err
	} else {
		return nil
	}
}

func init() {
	rootCmd.AddCommand(versionCmd)
	rootCmd.AddCommand(monitor.NewMonitorCmd())
}
