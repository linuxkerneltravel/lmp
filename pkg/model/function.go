package model

import (
	"github.com/cihub/seelog"
	initDB "lmp/common/mysql"
)

func (user *UserModel) Save() int64 {
	result, e := initDB.Db.Exec("insert into ginhello.user (username, password) values (?,?);", user.Username, user.Password)
	if e != nil {
		seelog.Error("user insert error", e.Error())
	}
	id, err := result.LastInsertId()
	if err != nil {
		seelog.Error("user insert id error", err.Error())
	}
	return id
}


func (user *UserModel) QueryByEmail() UserModel {
	u := UserModel{}
	row := initDB.Db.QueryRow("select * from user where username = ?;", user.Username)
	e := row.Scan(&u.Username, &u.Password)
	if e != nil {
		seelog.Warn(e)
	}
	return u
}