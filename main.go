package main

import (
	"context"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/facebookgo/pidfile"
	"github.com/linuxkerneltravel/lmp/logger"
	"github.com/linuxkerneltravel/lmp/models"
	"github.com/linuxkerneltravel/lmp/routes"
	"github.com/linuxkerneltravel/lmp/settings"
	"go.uber.org/zap"
)

func showlogo() {
	logo, err := ioutil.ReadFile("./misc/lmp.logo")
	if err != nil {
		fmt.Print(err)
	}

	fmt.Print(string(logo))
}

func main() {
	showlogo()

	pidfile.SetPidfilePath(os.Args[0] + ".pid")
	pidfile.Write()

	if err := settings.Init(); err != nil {
		fmt.Println("Init settings failed, err:", err)
		return
	}

	if err := logger.Init(settings.Conf.LogConfig, settings.Conf.AppConfig.Mode); err != nil {
		fmt.Println("Init logger failed, err:", err)
		return
	}
	defer zap.L().Sync()

	/*
		if err := influxdb.Init(settings.Conf.InfluxdbConfig); err != nil {
			fmt.Println("Init influxdb failed, err:", err)
			return
		}
	*/

	bpfscan := &models.BpfScan{}
	if err := bpfscan.Init(); err != nil {
		fmt.Println("Init bpfscan failed, err:", err)
	}
	bpfscan.Run()
	bpfscan.Watch()

	r := routes.SetupRouter(settings.Conf.AppConfig.Mode)

	srv := &http.Server{
		Addr:    fmt.Sprintf(":%d", settings.Conf.AppConfig.Port),
		Handler: r,
	}

	go func() {
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			zap.L().Error("listen failed :", zap.Error(err))
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit
	zap.L().Info("shutdown server ...")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := srv.Shutdown(ctx); err != nil {
		zap.L().Error("Server shutdown", zap.Error(err))
	}

	zap.L().Info("Server exiting")
}
