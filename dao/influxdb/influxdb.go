package influxdb

import (
	"fmt"
	client "github.com/influxdata/influxdb1-client/v2"
	"go.uber.org/zap"
	"lmp/settings"
)

var db client.Client

func Init(cfg *settings.InfluxdbConfig) (err error) {
	db, err = client.NewHTTPClient(client.HTTPConfig{
		Addr:     fmt.Sprintf("http://%s:%d", cfg.Host, cfg.Port),
		Username: cfg.User,
		Password: cfg.Password,
	})
	if err != nil {
		zap.L().Error("connect Influxdb failed", zap.Error(err))
		return err
	}
	return nil
}
