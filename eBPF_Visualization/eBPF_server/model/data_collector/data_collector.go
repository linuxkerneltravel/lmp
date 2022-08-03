package data_collector

import (
	"io"
	"lmp/server/model/data_collector/dao"
	"lmp/server/model/data_collector/logic"
)

var Tableinfo dao.TableInfo

func InitCollectSqlite() error {
	if err := dao.InitSqlite(); err != nil {
		return err
	}
	return nil
}

func DataCollectorEnter(pluginname string, stout io.ReadCloser) error {
	Tableinfo.TableName = pluginname
	if err := Tableinfo.CreateTable(); err != nil {
		return err
	}
	if err := logic.RediectStdout(stout, &Tableinfo); err != nil {
		return err
	}
	return nil
}
