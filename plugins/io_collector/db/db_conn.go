package db

import (
	"database/sql"
	_ "github.com/go-sql-driver/mysql"
	"log"
	"strings"
)

//数据库配置
const (
	userName = "root"
	password = "root"
	ip = "127.0.0.1"
	port = "3306"
	dbName = "tuner"
)
//Db数据库连接池
var DB *sql.DB

func InitDB()  {
	//构建连接："用户名:密码@tcp(IP:端口)/数据库?charset=utf8"
	path := strings.Join([]string{userName, ":", password, "@tcp(",ip, ":", port, ")/", dbName, "?charset=utf8"}, "")

	//打开数据库,前者是驱动名，所以要导入： _ "github.com/go-sql-driver/mysql"
	DB, _ = sql.Open("mysql", path)
	//设置数据库最大连接数
	DB.SetConnMaxLifetime(10)
	//设置上数据库最大闲置连接数
	DB.SetMaxIdleConns(5)
	//验证连接
	if err := DB.Ping(); err != nil{
		log.Fatalf("Connnect database fail! %+v",err)
		return
	}
	log.Println("Connnect Mysql Success!")
}
