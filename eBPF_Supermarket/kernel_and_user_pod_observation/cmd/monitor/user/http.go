package user

import (
	"github.com/spf13/cobra"
)

func NewMonitorUserHttpCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "http",
		Short:   "Starts monitor for pod by HTTP probes.",
		Long:    "",
		Example: "kupod monitor user http --pod sidecar-demo",
		RunE: func(cmd *cobra.Command, args []string) error {
			// 在这里写HTTP监控逻辑
			return nil
		},
	}

	return cmd
}
