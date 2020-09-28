package main

import (
	"fmt"
	"github.com/facebookgo/pidfile"
	"go.uber.org/zap"
	"lmp/models"
	"lmp/pkg/snowflake"
	"os"
	"lmp/logger"
	"lmp/routes"
	"lmp/settings"
	"lmp/dao/mysql"
)

func main() {
	fmt.Println(models.Logo)

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

	if err := mysql.Init(settings.Conf.MySQLConfig); err != nil {
		fmt.Println("Init mysql failed, err:", err)
		return
	}
	defer mysql.Close()

	bpfscan := &models.BpfScan{}
	if err := bpfscan.Init(); err != nil {
		fmt.Println("Init bpfscan failed, err:", err)
	}
	bpfscan.Run()
	bpfscan.Watch()

	if err := snowflake.Init(settings.Conf.StartTime, settings.Conf.MachineID); err != nil {
		fmt.Println("Init snowflake failed, err:", err)
		return
	}

	r := routes.SetupRouter(settings.Conf.AppConfig.Mode)
	err := r.Run(fmt.Sprintf(":%d", settings.Conf.AppConfig.Port))
	if err != nil {
		fmt.Printf("run server failed, err:%v\n", err)
		return
	}

	// 测试配置文件读取是否正确
	//fmt.Printf("Conf:%#v\n", settings.Conf.AppConfig)
	//fmt.Printf("Conf:%#v\n", settings.Conf.LogConfig)

	//srv := &http.Server{
	//	Addr:    fmt.Sprintf(":%d", settings.Conf.AppConfig.Port),
	//	Handler: r,
	//}
	//
	//go func() {
	//	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
	//		zap.L().Error("listen failed :", zap.Error(err))
	//	}
	//}()
	//
	//quit := make(chan os.Signal, 1)
	//signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	//<-quit
	//zap.L().Info("shutdown server ...")
	//ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	//defer cancel()
	//
	//if err := srv.Shutdown(ctx); err != nil {
	//	zap.L().Error("Server shutdown", zap.Error(err))
	//}
	//
	//zap.L().Info("Server exiting")
}
