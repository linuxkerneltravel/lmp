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
	"lmp/config"
	"lmp/common/influxdb"
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
		ticker := time.NewTicker(time.Second * 1) // 运行时长
		go func() {
			for {
				select {
				case <-ticker.C:
					fmt.Println(bpf.PluginServices)
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
