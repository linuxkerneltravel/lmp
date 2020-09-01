package main

import (
	"github.com/cihub/seelog"
	"github.com/facebookgo/grace/gracehttp"
	"github.com/facebookgo/pidfile"
	"github.com/urfave/cli"
	"net/http"
	"os"
	"time"

	"lmp/Rebuild/common/config"
)

func cliAction(c *cli.Context) error {
	logger, _ := seelog.LoggerFromConfigAsBytes([]byte(logtoconsoleconf))
	seelog.ReplaceLogger(logger)
	defer seelog.Flush()

	pidfile.SetPidfilePath(os.Args[0] + ".pid")
	pidfile.Write()

	config.InHost = c.String("inhost")
	config.Outhost = c.String("outhost")
	config.Port = c.String("port")

	listenAddress := config.InHost + ":" + config.Port
	config.GrafanaIp = config.Outhost + ":" + "3000"
	seelog.Info("Serve on ", listenAddress)
	seelog.Info("grafana on", config.GrafanaIp)

	return gracehttp.Serve(&http.Server{
		Addr:         listenAddress,
		Handler:      gracehttpHandler,
		ReadTimeout:  100 * time.Second,
		WriteTimeout: 100 * time.Second,
	})
}

func gracehttpHandler() {

}
