package influxdb

import (
	"fmt"

	"github.com/linuxkerneltravel/lmp/pkg/logger"
	"github.com/linuxkerneltravel/lmp/pkg/settings"

	client "github.com/influxdata/influxdb1-client/v2"
)

var db client.Client

func Init(cfg *settings.InfluxdbConfig) (err error) {
	db, err = client.NewHTTPClient(client.HTTPConfig{
		Addr:     fmt.Sprintf("http://%s:%d", cfg.Host, cfg.Port),
		Username: cfg.User,
		Password: cfg.Password,
	})
	if err != nil {
		logger.Error("connect Influxdb failed", err)
		return err
	}
	return nil
}

// 根据用户名建库
func CreatDatabase(dataBaseName string) (err error) {
	query := client.NewQuery(fmt.Sprintf("CREATE DATABASE %s", dataBaseName), "", "")
	_, err = db.Query(query)
	if err != nil {
		logger.Error("ERROR in CreatDatabase:", err)
		return err
	}
	//zap输出
	logger.Info(fmt.Sprintf("create database succeed,%s", dataBaseName))
	return
}
