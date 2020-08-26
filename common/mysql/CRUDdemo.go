package mysql

import (
	"fmt"
	"database/sql"
	"time"

	_ "github.com/go-sql-driver/mysql"
)

// 定义一个全局对象db
var db *sql.DB

// 定义user结构体
type user struct {
	id int
	age int
	name string
}

// 定义一个初始化数据库的函数
func initDB() (err error) {
	// DSN:Data Source Name
	dsn := "user:password@tcp(127.0.0.1:3306)/sql_test?charset=utf8mb4&parseTime=True"
	// 不会校验账号密码是否正确
	// 注意！！！这里不要使用:=，我们是给全局变量赋值，然后在main函数中使用全局变量db
	// 返回值已经定义了err，所以err也不用定义了
	db, err = sql.Open("mysql", dsn)
	if err != nil {
		return err
	}
	db.SetConnMaxLifetime(time.Second * 10)
	db.SetMaxIdleConns(5)
	db.SetMaxOpenConns(10)

	// 尝试与数据库建立连接（校验dsn是否正确）
	err = db.Ping()
	if err != nil {
		return err
	}

	fmt.Println("connect success")
	return nil
}

// 单行查询函数原型：
// func (db *DB) QueryRow(query string, args ...interface{}) *Row
func queryRowDemo() {
	sqlStr := "select id, name, age from user where id=?"
	var u user
	// 调用Query后不调用Scan那么这个数据库连接就会一直连接着，不会释放
	err := db.QueryRow(sqlStr, 1).Scan(&u.id, &u.name, &u.age)
	if err != nil {
		fmt.Printf("scan failed, err:%v\n", err)
		return
	}
	fmt.Printf("id:%d name:%s age:%d\n", u.id, u.name, u.age)
}

// 多行查询
func queryMultiRowDemo() {
	sqlStr := "select id, name, age from user where id>?"
	rows, err := db.Query(sqlStr, 0)
	if err != nil {
		fmt.Println("query failed, err:%v\n", err)
		return
	}
	// 关闭rows释放所有的数据库连接, 因为不能保证下面的for循环能够执行完，也就是不保证rows能顺利全部释放
	defer rows.Close()

	// 循环读取结果集中的数据
	for rows.Next() {
		var u user
		err := rows.Scan(&u.id, &u.name, &u.age)
		if err != nil {
			fmt.Printf("scan failed, err:%v\n", err)
			return
		}
		fmt.Printf("id:%d name:%s age:%d\n", u.id, u.name, u.age)
	}
}

// 插入、更新、删除数据函数原型：
// func (db *DB) Exec(query string, args ...interface{}) (Result, error)
func insertRowDemo() {
	sqlStr := "insert into user(name,age) values (?,?)"
	ret,err := db.Exec(sqlStr, "batman", 120)
	if err != nil {
		fmt.Printf("insert failed, err:%v\n", err)
		return
	}
	// 获取新插入数据的ID
	theID, err := ret.LastInsertId()
	if err != nil {
		fmt.Printf("get lastinsert ID failed, err:%v\n", err)
		return
	}
	fmt.Printf("insert success, the id is %d.\n", theID)
}

// 更新数据
func updateRowDemo() {
	sqlStr := "update user set age=? where id = ?"
	ret, err := db.Exec(sqlStr, 39, 3)
	if err != nil {
		fmt.Printf("update failed, err:%v\n", err)
		return
	}
	n, err := ret.RowsAffected() // 操作影响的行数
	if err != nil {
		fmt.Printf("get RowsAffected failed, err:%v\n", err)
		return
	}
	fmt.Printf("update success, affected rows:%d\n", n)
}

func deleteRowDemo() {
	sqlStr := "delete from user where id=?"
	ret, err := db.Exec(sqlStr, 3)
	if err != nil {
		fmt.Println("delete failed, err:%v\n", err)
		return
	}
	n, err := ret.RowsAffected()
	if err != nil {
		fmt.Printf("get RowsAffected failed, err:%v\n", err)
		return
	}
	fmt.Println("delete success, affected rows:%d\n", n)
}

/*
	普通SQL语句执行过程：

	客户端对SQL语句进行占位符替换得到完整的SQL语句。
	客户端发送完整SQL语句到MySQL服务端
	MySQL服务端执行完整的SQL语句并将结果返回给客户端。
*/
/*
	预处理执行过程：

	把SQL语句分成两部分，命令部分与数据部分。
	先把命令部分发送给MySQL服务端，MySQL服务端进行SQL预处理。
	然后把数据部分发送给MySQL服务端，MySQL服务端对SQL语句进行占位符替换。
	MySQL服务端执行完整的SQL语句并将结果返回给客户端。
*/
/*
	预处理的好处：

	1、优化MySQL服务器重复执行SQL的方法，可以提升服务器性能，提前让服务器编译，一次编译多次执行，节省后续编译的成本。
	2、避免SQL注入问题。
*/
// 预处理函数原型
// func (db *DB) Prepare(query string) (*Stmt, error)
func prepareQueryDemo() {
	sqlStr := "select id, name, age from user where id > ?"
	stmt, err := db.Prepare(sqlStr)
	if err != nil {
		fmt.Printf("prepare failed, err:%v\n", err)
		return
	}
	defer stmt.Close()

	rows, err := stmt.Query(0)
	if err != nil {
		fmt.Printf("query failed, err:%v\n", err)
		return
	}
	defer rows.Close()

	// 循环读取结果
	for rows.Next() {
		var u user
		err := rows.Scan(&u.id, &u.name, &u.age)
		if err != nil {
			fmt.Printf("scan failed, err:%v\n", err)
			return
		}
		fmt.Printf("id:%d name:%s age:%d\n", u.id, u.name, u.age)
	}
}

// 事务相关函数原型
//func (db *DB) Begin() (*Tx, error)
//func (tx *Tx) Commit() error
//func (tx *Tx) Rollback() error
// 一个转账事务
func transactionDemo() {
	tx, err := db.Begin()		// 开启事务
	if err != nil {
		if tx != nil {
			tx.Rollback()		// 回滚
		}
		fmt.Printf("begin trans failed, err:%v\n", err)
		return
	}

	sqlStr1 := "update user set age=30 where id=?"
	ret1, err := tx.Exec(sqlStr1, 2)
	if err != nil {
		tx.Rollback()
		fmt.Printf("exec sql1 failed, err:%v\n", err)
		return
	}
	affRow1,err := ret1.RowsAffected()
	if err != nil {
		tx.Rollback()
		fmt.Printf("exec ret1.RowsAffected() failed, err:%v\n", err)
		return
	}

	sqlStr2 := "update user set age=30 where id=?"
	ret2, err := tx.Exec(sqlStr2, 4)
	if err != nil {
		tx.Rollback()
		fmt.Printf("exec sql2 failed, err:%v\n", err)
		return
	}
	affRow2,err := ret2.RowsAffected()
	if err != nil {
		tx.Rollback()
		fmt.Printf("exec ret1.RowsAffected() failed, err:%v\n", err)
		return
	}

	fmt.Println(affRow1, affRow2)
	if affRow1 == 1 && affRow2 == 1 {
		tx.Commit()
		fmt.Println("events success")
	} else {
		tx.Rollback()
		fmt.Println("events rollback")
	}

}


func test() {
	err := initDB() // 调用输出化数据库的函数
	if err != nil {
		fmt.Printf("init db failed,err:%v\n", err)
		return
	}
	defer db.Close()

	//queryRowDemo()
	//queryMultiRowDemo()
	//insertRowDemo()
	//updateRowDemo()
	//deleteRowDemo()
	//prepareQueryDemo()
	transactionDemo()
}
