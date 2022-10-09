package connect_sql

import (
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/schema"
)

var GLOBALDB *gorm.DB

func SqlConnect(sqlpath string) error {
	db, err := gorm.Open(sqlite.Open(sqlpath), &gorm.Config{
		NamingStrategy: schema.NamingStrategy{
			SingularTable: true,
		},
	})
	GLOBALDB = db
	return err
}
