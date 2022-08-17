package dao

import (
	"errors"
	"fmt"
	"time"

	"lmp/server/global"

	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/schema"
)

var GLOBALDB *gorm.DB

type Indextable struct {
	Id         int    `gorm:"primaryKey;unique;column:IndexID",json:"Id"`
	PluginName string `gorm:"not null;unique;column:pluginname"`
	StartTime  string `gorm:"column:StartTime"`
	FinalTime  string `gorm:"column:FinalTime"`
	State      bool   `gorm:"default:true;column:State"`
}

func ConnectSqlite() error {
	m := global.GVA_CONFIG.Sqlite
	var createdb gorm.Dialector
	if m.Dsn() != "" {
		createdb = sqlite.Open(m.Dsn())
	} else {
		createdb = sqlite.Open("/home/yuemeng/lmp/eBPF_Visualization/eBPF_server/model/data_collector/dao/tables/ebpfplugin.db")
	}
	db, err := gorm.Open(createdb, &gorm.Config{
		NamingStrategy: schema.NamingStrategy{
			SingularTable: true,
		},
	})
	GLOBALDB = db

	return err
}

func InitSqlite() error {
	if err := ConnectSqlite(); err != nil {
		return err
	}
	if GLOBALDB.Migrator().HasTable(&Indextable{}) {
		var plugins = []Indextable{}
		GLOBALDB.Model(&Indextable{}).Find(&plugins)
		for _, v := range plugins {
			if GLOBALDB.Migrator().HasTable(v.PluginName) {
				delsql := fmt.Sprintf("drop table %s", v.PluginName)
				if err := GLOBALDB.Exec(delsql).Error; err != nil {
					return err
				}
			}
		}
		GLOBALDB.Exec("drop table indextable")
	}
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
		StartTime:  time.Now().Format("2006-01-02 15:04:05"),
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

func UpdateFinalTime(pluginname string) error {
	finaltime := time.Now().Format("2006-01-02 15:04:05")
	err := GLOBALDB.Table("indextable").Where("pluginname=?", pluginname).Update("FinalTime", finaltime).Error
	if err != nil {
		return err
	}
	return nil
}

func ChangeState(pluginname string) {
	GLOBALDB.Table("indextable").Where("pluginname=?", pluginname).Update("State", false)
}

func FindAllRecord() []Indextable {
	var list []Indextable
	GLOBALDB.Table("indextable").Find(&list)
	return list
}
