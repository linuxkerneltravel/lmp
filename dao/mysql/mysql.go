package mysql

import (
	"fmt"

	"github.com/linuxkerneltravel/lmp/logger"
	"github.com/linuxkerneltravel/lmp/settings"

	_ "github.com/go-sql-driver/mysql"
	"github.com/jmoiron/sqlx"
)

var db *sqlx.DB

func Init(cfg *settings.MySQLConfig) (err error) {
	dsn := fmt.Sprintf("%s:%s@tcp(%s:%d)/%s?charset=utf8mb4&parseTime=True",
		cfg.User,
		cfg.Password,
		cfg.Host,
		cfg.Port,
		cfg.Dbname,
	)

	db, err = sqlx.Connect("mysql", dsn)
	if err != nil {
		logger.Error("connect Mysql failed", err)
		return err
	}
	db.SetMaxOpenConns(settings.Conf.MySQLConfig.MaxOpenConns)
	db.SetMaxIdleConns(settings.Conf.MySQLConfig.MaxIdleConns)
	return nil
}

func Close() {
	_ = db.Close()
}
