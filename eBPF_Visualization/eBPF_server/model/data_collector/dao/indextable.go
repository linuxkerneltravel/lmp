package dao

import (
	"errors"
	"fmt"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/schema"
)

var GLOBALDB *gorm.DB

type Indextable struct {
	Id         int    `gorm:"primaryKey;unique;column:IndexID"`
	PluginName string `gorm:"not null;unique;column:pluginname"`
}

func InitSqlite() error {
	//TODO 路径问题，将绝对路径改为相对路径
	createdb := sqlite.Open("/home/yuemeng/lmp/eBPF_Visualization/eBPF_server/model/data_collector/dao/tables/ebpfplugin.db")
	db, err := gorm.Open(createdb, &gorm.Config{
		NamingStrategy: schema.NamingStrategy{
			SingularTable: true,
		},
	})
	if err != nil {
		return err
	}
	if db.Migrator().HasTable(&Indextable{}) {
		var plugins = []Indextable{}
		db.Model(&Indextable{}).Find(&plugins)
		for _, v := range plugins {
			if db.Migrator().HasTable(v.PluginName) {
				delsql := fmt.Sprintf("drop table %s", v.PluginName)
				if err := db.Exec(delsql).Error; err != nil {
					return err
				}
			}
		}
		db.Exec("drop table indextable")
	}
	GLOBALDB = db
	if err := GLOBALDB.AutoMigrate(&Indextable{}); err != nil {
		return err
	}
	if GLOBALDB.Migrator().HasTable(&Indextable{}) != true {
		err := errors.New("create IndexTable failed")
		return err
	}
	return nil
}

func CreatePluginRecord(pluginname string) error {
	indexinfo := Indextable{
		PluginName: pluginname,
	}
	err := GLOBALDB.Create(&indexinfo).Model(&Indextable{}).Error
	return err
}

func DeletePluginRecord(pluginname string) error {
	err := GLOBALDB.Where("pluginname=?", pluginname).Delete(&Indextable{}).Error
	return err
}

func PluginRecordExist(pluginname string) bool {
	err := GLOBALDB.Where("pluginname=?", pluginname).Find(&Indextable{}).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return false
	}
	return true
}
