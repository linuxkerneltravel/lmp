package mysql

import (
	"fmt"
	"github.com/spf13/viper"
	"go.uber.org/zap"
	"lmp/settings"

	_ "github.com/go-sql-driver/mysql"
	"database/sql"
)

var db *sql.DB

func Init(cfg *settings.MySQLConfig) (err error) {
	dsn := fmt.Sprintf("%s:%s@tcp(%s:%d)/%s?charset=utf8mb4&parseTime=True",
		cfg.User,
		cfg.Password,
		cfg.Host,
		cfg.Port,
		cfg.Dbname,
	)

	db, err := sql.Open("mysql", dsn)
	if err != nil {
		zap.L().Error("connect DB failed", zap.Error(err))
		return err
	}
	db.SetMaxOpenConns(viper.GetInt("mysql.max_open_conns"))
	db.SetMaxIdleConns(viper.GetInt("mysql.max_idle_conns"))
	fmt.Println("mysql init success")
	return nil
}

func Close() {
	_ = db.Close()
}
