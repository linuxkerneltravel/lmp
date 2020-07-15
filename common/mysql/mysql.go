//
// Created by ChenYuZhao
//

package mysql

import (
	"database/sql"
	_ "github.com/go-sql-driver/mysql"
	"log"
)

var Db *sql.DB

func init() {
	var err error
	Db, err = sql.Open("mysql", "root:1234@tcp(127.0.0.1:3306)/ginhello")
	if err != nil {
		log.Panicln("err:", err.Error())
	}
	//设置最大连接数
	Db.SetMaxOpenConns(20)
	//设置最大空闲连接数
	Db.SetMaxIdleConns(20)
}
