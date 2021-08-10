package dao

import (
	"collector/src/db"
	"log"
	"strconv"
)

type Dict struct {
	Id    int64
	Name  string
	Num   int
	ArgId int
}

func (this * Dict)String() string{
	return "id:"+  strconv.FormatInt(this.Id,11)+", name:"+this.Name+", Num:"+strconv.Itoa(this.Num)+", ArgId:"+strconv.Itoa(this.ArgId)
}


//查询操作
func QueryByNumAndArgID(num int ,argId int) (dict Dict, err error){
	stmt, e := db.DB.Prepare("select id,name,num,arg_id from dict where arg_id=? and num=?")
	if e!=nil {
		log.Fatalf("query incur error: %+v", e)
	}
	defer stmt.Close()
	query := stmt.QueryRow(argId,num)
	err = query.Scan(&dict.Id,&dict.Name, &dict.Num,&dict.ArgId)
	return
}
