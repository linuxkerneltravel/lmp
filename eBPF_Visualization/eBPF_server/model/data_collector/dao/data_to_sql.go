package dao

import (
	"errors"
	"fmt"
	"gorm.io/gorm"
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

func (ti TableInfo) CreateTable() error {
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

func (ti TableInfo) AppendTableByIndx(index string) (error, TableInfo) {
	parms := strings.Fields(index)
	ti.IndexName = make([]string, len(parms))
	ti.IndexType = make([]string, len(parms))
	for i, value := range parms {
		info := strings.Split(value, SpliteCharacter)
		ti.IndexName[i] = check.EscapeData(info[0])
		ti.IndexType[i] = check.EscapeData(info[1])
	}
	for i, _ := range ti.IndexName {
		addcollumnsql := fmt.Sprintf("alter table %s add column \"%s\" %s", ti.TableName, ti.IndexName[i], ti.IndexType[i])
		if err := GLOBALDB.Exec(addcollumnsql).Error; err != nil {
			return err, ti
		}
	}
	return nil, ti
}

func (ti TableInfo) AppenTableByData(index string, line string) (error, TableInfo) {
	index_parms := strings.Fields(index)
	elements := strings.Fields(line)
	type_parms := make([]string, len(index_parms))
	if len(elements) != len(type_parms) {
		err := errors.New("Indexes and output do not match, cannot write to database!")
		return err, ti
	}
	for i, element := range elements {
		type_parms[i] = check.GetTypeFromData(element)
	}
	ti.IndexName = make([]string, len(index_parms))
	ti.IndexType = make([]string, len(index_parms))
	for i, _ := range index_parms {
		ti.IndexName[i] = check.EscapeData(index_parms[i])
		ti.IndexType[i] = check.EscapeData(type_parms[i])
	}
	if check.OutNumberMatched(line, len(ti.IndexName)) {
		for i, _ := range ti.IndexName {
			addcollumnsql := fmt.Sprintf("alter table %s add column \"%s\" %s", ti.TableName, ti.IndexName[i], ti.IndexType[i])
			if err := GLOBALDB.Exec(addcollumnsql).Error; err != nil {
				return err, ti
			}
		}
	} else {
		err := errors.New("Indexes and output do not match, cannot write to database!")
		return err, ti
	}
	return nil, ti
}

func (ti TableInfo) InsertRow(line string) error {
	SingleLineDate := strings.Fields(line)
	DataKV := make(map[string]interface{}, len(SingleLineDate))
	for i, v := range SingleLineDate {
		DataKV[ti.IndexName[i]] = v
	}
	if err := GLOBALDB.Transaction(func(tx *gorm.DB) error {
		if err := tx.Table(ti.TableName).Create(DataKV).Error; err != nil {
			return err
		}
		return nil
	}); err != nil {
		return err
	}
	if err := UpdateFinalTime(ti.TableName); err != nil {
		return err
	}
	return nil
}
