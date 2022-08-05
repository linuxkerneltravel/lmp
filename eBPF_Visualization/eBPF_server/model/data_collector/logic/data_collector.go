package logic

import (
	"fmt"
	"lmp/server/model/data_collector/dao"
)

var Tableinfo dao.TableInfo

func InitCollectSqlite() error {
	if err := dao.InitSqlite(); err != nil {
		return err
	}
	return nil
}

func DataCollectorIndexType(pluginname string, index string, line string) (error, dao.TableInfo) {
	var tableinfo dao.TableInfo
	tableinfo.TableName = pluginname
	var err error
	if err = tableinfo.CreateTable(); err != nil {
		return err, tableinfo
	}
	if err, tableinfo = tableinfo.AppendTable(index, line); err != nil {
		return err, Tableinfo
	}
	fmt.Println(tableinfo)
	return nil, tableinfo
}

func DataCollectorRow(tableinfo dao.TableInfo, line string) error {
	if err := tableinfo.InsertRow(line); err != nil {
		return err
	}
	return nil
}
