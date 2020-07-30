package main

import (
	"github.com/cihub/seelog"
	"github.com/urfave/cli"
	"lmp/Rebuild/common/config"
	"os"
)

const (
	usageInfo = `LMP`
)

const (
	logtoconsoleconf = `
	<seelog>
		<outputs>
			<console formatid="out"/>
		</outputs>
		<formats>
		    <format id="out" format="[%Level] %File:%Line %Func %Msg%n"/>
		</formats>
	</seelog>
	`
)

func doBeforeJob(ctx *cli.Context) error {
	return nil
}

func main() {
	app := cli.NewApp()
	app.Name = "LMP"
	app.Usage = usageInfo
	app.Version = config.Version
	app.Action = handler

	app.Flags = config.Flags
	app.Before = doBeforeJob
	err := app.Run(os.Args)
	if err != nil {
		seelog.Error("Start LMP failed...")
	}
}



