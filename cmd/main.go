//
// Created by Chenyu Zhao
// Modified by Zhenwen Xu
// Modified by ChenYuZhao on 2020/7/3.
// Modified by Qiangzhixing Cheng
//
package main

import (
	"fmt"
	bpf "lmp/internal/BPF"
	"math/rand"
	"net/http"
	"os"
	"runtime/debug"
	"time"

	"lmp/api"
	"lmp/common/influxdb"
	"lmp/config"
	"lmp/daemon"

	"github.com/cihub/seelog"
	"github.com/facebookgo/grace/gracehttp"
	"github.com/facebookgo/pidfile"
	"github.com/gin-gonic/contrib/static"
	"github.com/gin-gonic/gin"
	"github.com/urfave/cli"
)

func main() {
	rand.Seed(time.Now().UnixNano())
	debug.SetTraceback("crash")
	app := cli.NewApp()
	app.Name = "lmp"
	app.Usage = "lmp"
	app.Flags = config.Flags
	app.Action = func(c *cli.Context) error {
		logger, _ := seelog.LoggerFromConfigAsBytes([]byte(logtoconsoleconf))
		seelog.ReplaceLogger(logger)
		defer seelog.Flush()
		config.Initialize(c)

		pidfile.SetPidfilePath(os.Args[0] + ".pid")
		pidfile.Write()

		influxStore := influxdb.NewInfluxStore()
		influxStore.Init()

		//bpf scan service
		bpfscan := &daemon.BpfScan{}
		bpfscan.Init()
		bpfscan.Run()

		srv := api.NewServer(c)
		srv.Use(static.Serve("/", static.LocalFile("static", false)))
		srv.StaticFS("/static", http.Dir("static/"))
		srv.NoRoute(func(c *gin.Context) {
			c.File(fmt.Sprintf("%s/file.html", "static"))
		})

		config.InHost = c.String("inhost")
		config.Outhost = c.String("outhost")
		config.Port = c.String("port")
		
		listenAddress := config.InHost + ":" + config.Port
		config.GrafanaIp = config.Outhost + ":" + "3000"
		seelog.Info("Serve on ", listenAddress)

		// The following timer code is used to test the plug-in mechanism, If you like to delete it, delete it
		ticker := time.NewTicker(time.Second * 15) // 运行时长
		go func() {
			for {
				select {
				case <-ticker.C:
					// 该处可以用来反馈给用户目前支持的插件
					fmt.Println(bpf.PluginServices)
					//for _,plugin := range bpf.PluginServices {
						//fmt.Println(plugin.Name)
						//fmt.Println(plugin.Info)
						//fmt.Println(plugin.F)
					//}
					//fmt.Println(bpf.PluginServices[1].Name)
				}
			}
			ticker.Stop()
		}()

		return gracehttp.Serve(&http.Server{
			Addr:         listenAddress,
			Handler:      srv,
			ReadTimeout:  100 * time.Second,
			WriteTimeout: 100 * time.Second,
		})
	}
	app.Run(os.Args)
}

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
