package modules

import (
	"fmt"

	"github.com/urfave/cli/v2"
)

func init() {
	if err := registerModules(&profileClusterCommand); err != nil {
		fmt.Printf("Failed to register module : %s\n", err)
		return
	}
}

var profileClusterCommand = cli.Command{
	Name:      "cluster",
	Usage:     "Density peak clustering",
	ArgsUsage: "[APP_NAME]",

	Flags: []cli.Flag{
		&cli.StringFlag{
			Name:    "data",
			Aliases: []string{"d"},
			Usage:   "specified the the dataset to run",
			Value:   "",
		},
	},

	Description: func() string {
		desc := `
	 Density peak clustering, Can be used for anomaly detection.
		example: ./lmp cluster --data /YOUR_PATH
		example: ./lmp cluster -d /YOUR_PATH
	`
		return desc
	}(),
	Action: clusterPeak,
}

func clusterPeak(ctx *cli.Context) error {
	if ctx.NArg() > 2 {
		return fmt.Errorf("only one or zero argument required")
	}

	dataPath := ctx.String("data")
	fmt.Println("data path is: ", dataPath)

	// start a process and run your model

	return nil
}
