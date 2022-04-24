package dao

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"os/user"
	"strconv"
	"strings"

	"github.com/lmp/eBPF_Visualization/core_service/common"
	"github.com/lmp/eBPF_Visualization/core_service/globalver"
	"github.com/lmp/eBPF_Visualization/core_service/utils"

	"github.com/gwenn/yacr"
)

const (
	DBNAME = "LMP"
)

func CreateTableByTableInfo(tableInfo *common.TableInfo) {
	sql := fmt.Sprintf(`
	drop table if exists "%s";
	CREATE TABLE IF NOT EXISTS "%s"(
	  id INTEGER PRIMARY KEY NOT NULL
	);
	`, tableInfo.TableName, tableInfo.TableName)

	err := globalver.DB.Exec(sql)
	utils.CheckNormalError(err)
}

func AddIndex2Table(tableInfo *common.TableInfo) error {
	for k, v := range tableInfo.Indexes {
		sql := fmt.Sprintf(`
		ALTER TABLE %s ADD COLUMN %s %s;
		`, tableInfo.TableName, tableInfo.Indexes[k], tableInfo.INdexesInfo[v])

		err := globalver.DB.Exec(sql)
		utils.CheckNormalError(err)
	}

	return nil
}

func SaveData(tableInfo *common.TableInfo, line string) error {
	// create sql
	var questionMarkString string
	for _, _ = range tableInfo.Indexes {
		questionMarkString += "?, "
	}
	questionMarkString = questionMarkString[:len(questionMarkString)-2]

	var columns string
	for _, v := range tableInfo.Indexes {
		columns += v + ", "
	}
	columns = columns[:len(columns)-2]

	sql := fmt.Sprintf(`
		insert into %s(%s) values(%s);
		`, tableInfo.TableName, columns, questionMarkString)

	parms := strings.Fields(line)
	fmt.Println(sql, "\n", parms)
	//globalver.DB.Begin()
	//for i := 0; i < 1000; i++ {
	newParms := make([]interface{}, len(parms))
	for i, v := range parms {
		newParms[i] = v
	}
	globalver.DB.Exec(sql, newParms...)
	//globalver.DB.Changes()
	//}
	//globalver.DB.Commit()

	return nil
}

func GenerateCsvFile(tableInfo *common.TableInfo) {
	// TODO: break while < 5
	var b bytes.Buffer
	w := yacr.NewWriter(&b, ',', true)
	err := globalver.DB.ExportTableToCSV("", tableInfo.TableName, "", true, w)
	if err != nil {
		fmt.Println("err", err)
	}

	file, err := os.OpenFile(fmt.Sprintf("%s.csv", tableInfo.TableName), os.O_CREATE|os.O_WRONLY, 0666)
	if err != nil {
		fmt.Println("Open file err =", err)
		return
	}
	u, _ := user.Lookup("zcy")
	uid, _ := strconv.Atoi(u.Uid)
	gid, _ := strconv.Atoi(u.Gid)
	file.Chown(uid, gid)
	writer := bufio.NewWriter(file)
	writer.Write(b.Bytes())
	writer.Flush()
	if err != nil {
		return
	}
}
