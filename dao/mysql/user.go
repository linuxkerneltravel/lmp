package mysql

import (
	"crypto/md5"
	"database/sql"
	"encoding/hex"
	"fmt"

	"lmp/models"
	"lmp/pkg/snowflake"
)

const secret = "LMP"

func encryptPassword(data []byte) (result string) {
	h := md5.New()
	h.Write([]byte(secret))
	return hex.EncodeToString(h.Sum(data))
}

func CheckUserExist(username string) error {
	sqlStr := `select count(user_id) from user where username = ?`
	var count int
	fmt.Println("hello\n")

	//if err := db.QueryRow(&count, sqlStr, username); err != nil {
	//	return err
	//}
	if err := db.QueryRow(sqlStr, 1).Scan(&count); err != nil {
		return err
	}
	if count > 0 {
		return ErrorUserExit
	}
	return nil
}

func Register(user *models.User) (err error) {
	sqlStr := `select count(user_id) from user where username = ?`
	var count int64
	err = db.Get(&count, sqlStr, user.Username)
	if err != nil && err != sql.ErrNoRows {
		return err
	}
	if count > 0 {
		// 用户已存在
		return ErrorUserExit
	}
	// 生成user_id
	userID := snowflake.GenID()
	if err != nil {
		return ErrorGenIDFailed
	}
	// 生成加密密码
	password := encryptPassword([]byte(user.Password))
	// 把用户插入数据库
	sqlStr = `insert into user(user_id, username, password) values (?,?,?)`
	//_, err = db.Exec(sqlStr, 999, "superman", 123)
	_, err = db.Exec(sqlStr, userID, user.Username, password)
	return
}

func InsertUser(user *models.User) (err error) {
	user.Password = encryptPassword([]byte(user.Password))
	//sqlStr := `insert into user(user_id, username, password) values(? ? ?)`
	//_, err = db.Exec(sqlStr, user.UserID, user.Username, user.Password)
	//return

	sqlStr := `insert into user(user_id, username, password) values (?,?,?)`
	ret, err := db.Exec(sqlStr, user.UserID, user.Username, user.Password)
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

	return
}

func Login(user *models.User) (err error) {
	originPassword := user.Password // 记录一下原始密码
	sqlStr := `select user_id, username, password from user where username = ?`
	err = db.Get(user, sqlStr, user.Username)
	if err != nil && err != sql.ErrNoRows {
		// 查询数据库出错
		return
	}
	if err == sql.ErrNoRows {
		// 用户不存在
		return ErrorUserNotExit
	}
	// 生成加密密码与查询到的密码比较
	password := encryptPassword([]byte(originPassword))
	if user.Password != password {
		return ErrorInvalidPassword
	}
	return
}
