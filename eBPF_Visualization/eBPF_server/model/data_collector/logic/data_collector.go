package logic

import (
	"lmp/server/model/data_collector/dao"
)

var Tableinfo dao.TableInfo

func InitCollectSqlite() error {
	if err := dao.InitSqlite(); err != nil {
		return err
	}
	return nil
}

func DataCollectorIndex(pluginname string, index string) error {
	Tableinfo.TableName = pluginname
	if err := Tableinfo.CreateTable(); err != nil {
		return err
	}
	if err := Tableinfo.AppendTable(index); err != nil {
		return err
	}
	return nil
}

func DataCollectorRow(line string) error {
	if err := Tableinfo.InsertRow(line); err != nil {
		return err
	}
	return nil
}
