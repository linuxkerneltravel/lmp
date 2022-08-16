package logic

import (
	"errors"
	"fmt"
	"lmp/server/model/data_collector/check"
	"lmp/server/model/data_collector/dao"
)

var Tableinfo dao.TableInfo

func InitCollectSqlite() error {
	if err := dao.InitSqlite(); err != nil {
		return err
	}
	return nil
}

func DataCollectorIndexFromIndex(pluginname string, index string) (error, dao.TableInfo) {
	var tableinfo dao.TableInfo
	tableinfo.TableName = pluginname
	var err error
	if err = tableinfo.CreateTable(); err != nil {
		return err, tableinfo
	}
	if err, tableinfo = tableinfo.AppendTableByIndx(index); err != nil {
		return err, Tableinfo
	}
	fmt.Println(tableinfo)
	return nil, tableinfo
}

func DataCollectorIndexFromData(pluginname string, index string, line string) (error, dao.TableInfo) {
	var tableinfo dao.TableInfo
	tableinfo.TableName = pluginname
	var err error
	if err = tableinfo.CreateTable(); err != nil {
		return err, tableinfo
	}
	if err, tableinfo = tableinfo.AppenTableByData(index, line); err != nil {
		return err, Tableinfo
	}
	fmt.Println(tableinfo)
	return nil, tableinfo
}

func DataCollectorRow(tableinfo dao.TableInfo, line string) error {
	if check.OutNumberMatched(line, len(tableinfo.IndexName)) {
		if err := tableinfo.InsertRow(line); err != nil {
			return err
		}
	} else {
		err := errors.New("Indexes and output do not match, cannot write to database!")
		return err
	}
	return nil
}
