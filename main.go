package main

import (
	"context"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"os/signal"
	"sort"
	"syscall"
	"time"

	"github.com/linuxkerneltravel/lmp/dao/mysql"
	"github.com/linuxkerneltravel/lmp/logger"
	"github.com/linuxkerneltravel/lmp/modules"
	"github.com/linuxkerneltravel/lmp/routes"
	"github.com/linuxkerneltravel/lmp/settings"

	"github.com/facebookgo/pidfile"
	"github.com/urfave/cli/v2"
	"go.uber.org/zap"
)

func checkValid(ctx *cli.Context) error {
	return nil
}

func showlogo() {
	logo, err := ioutil.ReadFile("./misc/lmp.logo")
	if err != nil {
		fmt.Print(err)
	}

	fmt.Print(string(logo))
}

func doBeforeJob(ctx *cli.Context) error {
	if err := checkValid(ctx); err != nil {
		return err
	}

	pidfile.SetPidfilePath(os.Args[0] + ".pid")
	if err := pidfile.Write(); err != nil {
		fmt.Println("Pidfile write failed, err:", err)
		return err
	}

	if err := settings.Init(); err != nil {
		fmt.Println("Init settings failed, err:", err)
		return err
	}

	if err := logger.Init(settings.Conf.LogConfig, settings.Conf.AppConfig.Mode); err != nil {
		fmt.Println("Init logger failed, err:", err)
		return err
	}
	defer zap.L().Sync()

	if err := mysql.Init(settings.Conf.MySQLConfig); err != nil {
		fmt.Println("Init mysql failed, err:", err)
		return err
	}

	/*
		if err := influxdb.Init(settings.Conf.InfluxdbConfig); err != nil {
			fmt.Println("Init influxdb failed, err:", err)
			return err
		}
	*/

	return nil
}

func runlmp(ctx *cli.Context) error {
	if err := checkValid(ctx); err != nil {
		return err
	}

	r := routes.SetupRouter(settings.Conf.AppConfig.Mode)

	srv := &http.Server{
		Addr:    fmt.Sprintf(":%d", settings.Conf.AppConfig.Port),
		Handler: r,
	}

	showlogo()

	go func() {
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			zap.L().Error("listen failed :", zap.Error(err))
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit
	zap.L().Info("shutdown server ...")
	ctxx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := srv.Shutdown(ctxx); err != nil {
		zap.L().Error("Server shutdown", zap.Error(err))
	}

	zap.L().Info("Server exiting")

	return nil
}

func main() {
	app := cli.NewApp()

	app.Name = settings.Name
	app.Usage = settings.LmpUsage
	app.Version = settings.Version

	for _, v := range modules.GetModules() {
		app.Commands = append(app.Commands, v)
	}
	sort.Sort(cli.CommandsByName(app.Commands))

	app.Before = doBeforeJob
	app.Action = runlmp

	defer func() {
		// close mysql connection
		mysql.Close()
	}()

	if err := app.Run(os.Args); err != nil {
		fmt.Printf("%s\n", err)
		os.Exit(1)
	}

}
