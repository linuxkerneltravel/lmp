package config

import (
	"github.com/urfave/cli"
)

var Version = "no version right now"

// for cli's Flags
var Flags = []cli.Flag{
	cli.StringFlag{
		Name:  "inhost",
		Value: "0.0.0.0",
		Usage: "service listen inside ipaddress",
	},
	cli.StringFlag{
		Name:  "outhost",
		Value: "0.0.0.0",
		Usage: "service listen outside address",
	},
	cli.UintFlag{
		Name:  "port,p",
		Value: 8080,
		Usage: "service port",
	},
	cli.StringFlag{
		Name:  "mode,m",
		Value: "dev",
		Usage: "run mode",
	},
	// the config flag Not currently used
	cli.StringFlag{
		Name:  "config,c",
		Value: "",
		Usage: "configure file",
	},
}

var (
	InHost       string
	Outhost      string
	Port         string
	GrafanaIp    string
)
