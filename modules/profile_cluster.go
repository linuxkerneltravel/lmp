package modules

import (
	"fmt"

	"github.com/urfave/cli/v2"
)

func init() {
	OptModules.Modules = append(OptModules.Modules, &profileAnalysisCommand)
}

var profileAnalysisCommand = cli.Command{
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
		example: ./lmp cluster --model /YOUR_PATH
		example: ./lmp cluster -m /YOUR_PATH
	`
		return desc
	}(),
	Action: clusterPeak,
}

func clusterPeak(ctx *cli.Context) error {
	if ctx.NArg() > 2 {
		return fmt.Errorf("only one or zero argument required")
	}

	dataPath := ctx.String("model")
	fmt.Println("data path is: ", dataPath)

	// start a process and run your model

	return nil
}
