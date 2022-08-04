package dao

import (
	"errors"
	"fmt"
	"strings"

	"lmp/server/model/data_collector/check"
)

const SpliteCharacter = "|"

type TableInfo struct {
	TableName string
	IndexName []string
	IndexType []string
}

type BasicPluginInfo struct {
	ID int `gorm:"primaryKey;unique;column:ID"`
}

func (ti *TableInfo) CreateTable() error {
	if err := ConnectSqlite(); err != nil {
		return err
	}
	if PluginRecordExist(ti.TableName) {
		if err := DeletePluginRecord(ti.TableName); err != nil {
			return err
		}
	}
	deletetablesql := fmt.Sprintf("drop table if exists %s;", ti.TableName)
	if err := GLOBALDB.Exec(deletetablesql).Error; err != nil {
		return err
	}
	if err := GLOBALDB.Table(ti.TableName).AutoMigrate(&BasicPluginInfo{}); err != nil {
		return err
	}
	if GLOBALDB.Migrator().HasTable(ti.TableName) != true {
		err := errors.New("create PluginTable failed")
		return err
	}
	if err := CreatePluginRecord(ti.TableName); err != nil {
		return err
	}
	return nil
}

func (ti *TableInfo) AppendTable(index string) error {
	parms := strings.Fields(index)
	ti.IndexName = make([]string, len(parms))
	ti.IndexType = make([]string, len(parms))
	for i, value := range parms {
		if err := check.VerifyIndexFormat(value); err != nil {
			return err
		}
		info := strings.Split(value, SpliteCharacter)
		ti.IndexName[i] = check.EscapeData(info[0])
		ti.IndexType[i] = check.EscapeData(info[1])
	}
	for i, _ := range ti.IndexName {
		addcollumnsql := fmt.Sprintf("alter table %s add column \"%s\" %s", ti.TableName, ti.IndexName[i], ti.IndexType[i])
		if err := GLOBALDB.Exec(addcollumnsql).Error; err != nil {
			return err
		}
	}
	return nil
}

func (ti *TableInfo) InsertRow(line string) error {
	SingleLineDate := strings.Fields(line)
	values := make([]interface{}, len(SingleLineDate))
	for i, v := range SingleLineDate {
		values[i] = v
	}

	var columns string
	for _, v := range ti.IndexName {
		v = "\"" + check.EscapeData(v) + "\""
		columns += v + ", "
	}
	columns = columns[:len(columns)-2]

	insertsql := fmt.Sprintf("insert into %s(%s) values(?)", ti.TableName, columns)
	if err := GLOBALDB.Exec(insertsql, values).Error; err != nil {
		return err
	}
	return nil
}
