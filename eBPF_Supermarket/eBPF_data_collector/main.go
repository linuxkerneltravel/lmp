package main

import (
	"fmt"
	"log"
	"os"
	"os/user"
	"sort"

	"github.com/lmp/eBPF_Visualization/core_service/dao"
	"github.com/lmp/eBPF_Visualization/core_service/globalver"
	"github.com/lmp/eBPF_Visualization/core_service/services"
	"github.com/lmp/eBPF_Visualization/core_service/utils"

	sqlite "github.com/gwenn/gosqlite"
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

	app.Before = doBeforeJob
	err = app.Run(os.Args)
	if err != nil {
		log.Fatal(err)
	}
}

func doBeforeJob(ctx *cli.Context) (err error) {
	// ":memory:" for memory db, "" for temp file db
	os.Remove(dao.DBNAME)
	globalver.DB, err = sqlite.Open(dao.DBNAME)
	utils.CheckNormalError(err)

	//u, _ := user.Current()
	u, _ := user.Lookup("zcy")

	fmt.Println("当前用户")
	fmt.Printf("Gid %s\n", u.Gid)
	fmt.Printf("Uid %s\n", u.Uid)
	fmt.Printf("Username %s\n", u.Username)
	fmt.Printf("Name %s\n", u.Name)
	fmt.Printf("HomeDir %s\n", u.HomeDir)
	fmt.Println("")
	return nil
}
