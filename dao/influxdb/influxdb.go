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


// 根据用户名建库
func CreatDatabase(dataBaseName string){
	query := client.NewQuery(fmt.Sprintf("CREATE DATABASE %s", dataBaseName), "", "")
	response,err:=db.Query(query)
	if err!=nil{
		zap.L().Error(" ", zap.Error(err))
	}
	//zap输出
	fmt.Println(response)
}