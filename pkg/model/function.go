package model

import (
	initDB "lmp/common/mysql"
	"github.com/cihub/seelog"
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
