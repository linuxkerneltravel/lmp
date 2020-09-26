package main

import (
	"context"
	"fmt"
	"github.com/facebookgo/pidfile"
	"go.uber.org/zap"
	"lmp/models"
	"lmp/pkg/snowflake"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"lmp/logger"
	"lmp/routes"
	"lmp/settings"
)

// go 开发比较通用的脚手架

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

	// 3、初始化mysql
	//if err := mysql.Init(settings.Conf.MySQLConfig); err != nil {
	//	fmt.Println("Init mysql failed, err:", err)
	//	return
	//}
	//defer mysql.Close()
	// 4、初始化redis连接
	// 这个暂时先放下

	bpfscan := &models.BpfScan{}
	if err := bpfscan.Init(); err != nil {
		fmt.Println("Init bpfscan failed, err:", err)
	}
	bpfscan.Run()

	if err := snowflake.Init(settings.Conf.StartTime, settings.Conf.MachineID); err != nil {
		fmt.Println("Init snowflake failed, err:", err)
		return
	}

	// todo:翻译器，validator库参数校验若干实用技巧

	r := routes.SetupRouter(settings.Conf.AppConfig.Mode)

	// 测试配置文件读取是否正确
	//fmt.Printf("Conf:%#v\n", settings.Conf.AppConfig)
	//fmt.Printf("Conf:%#v\n", settings.Conf.LogConfig)

	srv := &http.Server{
		Addr:    fmt.Sprintf(":%d", settings.Conf.AppConfig.Port),
		Handler: r,
	}

	go func() {
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			zap.L().Error("listen failed :", zap.Error(err))
		}
	}()

	quit := make(chan os.Signal, 1)                      // 创建一个接收信号的通道
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM) // 这里不会阻塞
	<-quit                                               // 在这里阻塞，当接收到上面两种信号的时候才会往下进行
	zap.L().Info("shutdown server ...")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := srv.Shutdown(ctx); err != nil {
		zap.L().Error("Server shutdown", zap.Error(err))
	}

	zap.L().Info("Server exiting")
}
