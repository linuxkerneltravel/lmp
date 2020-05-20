package influxdb

//该文件写influxdb的全局变量和init

import(
	"github.com/cihub/seelog"
	"github.com/influxdata/influxdb/client/v2"
	"lmp/config"
)

//globe engine
var Conn client.Client

type InfluxStore struct {
	Cfg    *config.Cfg
	////读出文件的数据，把读出的文件的内容写入到rc。
	//rc    chan []byte
	////Process把rc的数据
	//wc    chan *Message
	//read  Reader
	//write Writer
}

func (i *InfluxStore) Init() error {
	Conn, err := client.NewHTTPClient(client.HTTPConfig{
		Addr:     config.InfluxdbAddr,
		Username: config.InfluxdbUsername,
		Password: config.InfluxdbPassword,
	})
	if err != nil {
		seelog.Error(err)
		return err
	}

	seelog.Info("connecting to influxdb...")
	q := client.NewQuery("create database log_process", "", "")
	_, err = Conn.Query(q)
	if err != nil {
		seelog.Error("create database log_process failed!")
		return err
	}
	seelog.Info("connecting to influxdb succeed")

	return nil
}

//热加载
func (i *InfluxStore) Reload() error {
	return nil
}
