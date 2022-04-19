package main

import (
	"fmt"
	"log"
	"os"
	"sort"

	"github.com/lmp/eBPF_Visualization/core_service/services"

	"github.com/urfave/cli"
)

func main() {
	app := cli.NewApp()
	app.Name = "lmp-cli"
	app.Usage = "a core service in LMP"

	err := services.WalkServices(func(nm string, svc *services.Service) error {
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
