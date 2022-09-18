package user

import "github.com/spf13/cobra"

func NewMonitorUserAllCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "all",
		Short:   "Monitor pod by all provided user tools.",
		Long:    "",
		Example: "kupod monitor user all --pod sidecar-demo ",
		RunE:    MonitorUserAll,
	}

	addMonitorUserAllCommand(cmd)

	return cmd
}

func addMonitorUserAllCommand(cmd *cobra.Command) {

}

func MonitorUserAll(cmd *cobra.Command, args []string) error {
	// 在这里写全部用户态监控逻辑
	return nil
}
