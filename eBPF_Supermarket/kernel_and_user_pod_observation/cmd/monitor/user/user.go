package user

import (
	"fmt"

	"github.com/spf13/cobra"
)

//外面的monitor调用是这里
func NewMonitorUserCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "user",
		Short:   "Starts monitor for pod from user mode.",
		Long:    "For User Mode Monitor",
		Example: "kupod monitor user all --pod sidecar-demo",

		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Println("\"kupod monitor user\" requires 1 argument.\nSee 'kupod monitor user --help'.")
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
	cmd.AddCommand(NewMonitorUserAllCmd())
	cmd.AddCommand(NewMonitorUserHttpCmd())
	// 在这里添加更多你的子命令
	cmd.AddCommand(NewMonitorUserGRPCCmd())
}
