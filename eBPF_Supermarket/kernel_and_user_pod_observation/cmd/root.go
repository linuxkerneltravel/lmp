package cmd

import (
	"github.com/spf13/cobra"

	"github.com/linuxkerneltravel/lmp/eBPF_Supermarket/kernel_and_user_pod_observation/cmd/monitor"
)

var rootCmd = &cobra.Command{
	Use:   "kupod",
	Short: "KUPOD is an eBPF-based tool for monitoring and visualization of pods from user mode and kernel mode",
	Long:  ``,
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
