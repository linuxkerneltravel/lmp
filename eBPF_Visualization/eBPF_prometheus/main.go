package main

import (
	"ebpf_prometheus/checker"
	"ebpf_prometheus/collector"
	"fmt"
	"github.com/urfave/cli/v2"
	"log"
	"os"
	"sort"
)

func main() {
	app := cli.NewApp()
	app.Name = "collect-cli"
	app.Usage = `
	use this cli-tool to collect output data and Convert output data to standard prometheus data.
	example:
		sudo ./collect-cli collect ./vfsstat.py
`
	err := collector.RunServices(func(nm string, svc *collector.Aservice) error {
		ins, err := svc.NewInst(nil)
		if err != nil {
			return err
		}
		cmd, ok := ins.(cli.Command)
		if !ok {
			fmt.Printf("service %s doesn't implement cli.Command\n", nm)
			return fmt.Errorf("service %s doesn't implement cli.Command\n", nm)
		}
		app.Commands = append(app.Commands, &cmd)
		return nil
	})
	sort.Sort(cli.CommandsByName(app.Commands))

	app.Before = doBeforeJob
	err = app.Run(os.Args)
	if err != nil {
		log.Fatal(err)
	}
}

func doBeforeJob(ctx *cli.Context) (err error) {
	checker.CheckNormalError(err)
	return nil
}
