package dao

import (
	"collector/src/db"
	"log"
	"strconv"
)

type Arg struct {
	Id    int
	Name  string
	Value  string
	ValType   int
	Path string
	PreId int
	PreArgVal string
}

func (this * Arg)String() string{
 return "id:"+  strconv.Itoa(this.Id)+", name:"+this.Name+", value:"+this.Value+", valType:"+strconv.Itoa(this.ValType)+", path:"+this.Path+", preid:"+strconv.Itoa(this.PreId)+", preArgVal:"+this.PreArgVal
}


//查询操作
func QueryArgList() []Arg{
	var args []Arg
	var arg = new(Arg)
	rows, e := db.DB.Query("select id,name,value,val_type,path,pre_id,pre_arg_val from args")
	if e != nil {
		log.Fatalf("query incur error: %+v", e)
		return nil
	}
	for rows.Next() {
		e := rows.Scan(&arg.Id,&arg.Name, &arg.Value,&arg.ValType, &arg.Path,&arg.PreId,&arg.PreArgVal )
		if e == nil {
			args = append(args,*arg)
		}
	}
	rows.Close()
	return args
	//db.DB.QueryRow("select * from arg where id=1").Scan(arg.age, arg.id, arg.name, arg.phone, arg.sex)
	//
	//stmt, e := db.DB.Prepare("select * from arg where id=?")
	//query, e := stmt.QueryArgList(1)
	//query.Scan()
}


func QueryArgByName(name string) *Arg{
	stmt, e := db.DB.Prepare("select id,name,value,val_type,path,pre_id,pre_arg_val from args where name=?")
	if e!=nil {
		log.Fatalf("query incur error: %+v", e)
	}
	query := stmt.QueryRow(name)
	var arg = new(Arg)
	query.Scan(&arg.Id,&arg.Name, &arg.Value,&arg.ValType, &arg.Path ,&arg.PreId,&arg.PreArgVal )

	stmt.Close()
	return arg
}
func QueryArgById(id int) *Arg{
	stmt, e := db.DB.Prepare("select id,name,value,val_type,path,pre_id,pre_arg_val from args where id=?")
	if e!=nil {
		log.Fatalf("query incur error: %+v", e)
	}
	query := stmt.QueryRow(id)
	var arg = new(Arg)
	query.Scan(&arg.Id,&arg.Name, &arg.Value,&arg.ValType, &arg.Path ,&arg.PreId,&arg.PreArgVal )

	stmt.Close()
	return arg
}





