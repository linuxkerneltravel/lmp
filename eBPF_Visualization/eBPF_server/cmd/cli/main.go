package main

import (
	"fmt"
	"log"
	"os"
	"sort"

	"lmp/server/clicore"

	"github.com/urfave/cli"
)

func main() {
	app := cli.NewApp()
	app.Name = "lmp-cli"
	app.Usage = "a core service in LMP"

	err := clicore.WalkServices(func(nm string, svc *clicore.CliService) error {
		ins, err := svc.NewInst(nil)
		if err != nil {
			return err
		}
		cmd, ok := ins.(cli.Command)
		if !ok {
			fmt.Printf("service %s doesn't implement cli.Command\n", nm)
			return fmt.Errorf("service %s doesn't implement cli.Command", nm)
		}

		app.Commands = append(app.Commands, cmd)

		return nil
	})

	sort.Sort(cli.CommandsByName(app.Commands))

	err = app.Run(os.Args)
	if err != nil {
		log.Fatal(err)
	}
}
