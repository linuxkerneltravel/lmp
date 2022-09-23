package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

var currentVersion string

// versionCmd represents the version command
var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print the version information",
	Long:  ``,
	Run: func(cmd *cobra.Command, args []string) {
		ver, err := getVersion()
		if err != nil {
			panic(err)
		}
		fmt.Println(ver)
	},
}

func getVersion() (string, error) {
	return currentVersion, nil
}
