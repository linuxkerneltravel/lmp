package unit_test

import (
	"fmt"
	"strings"
	"testing"

	"lmp/server/model/data_collector/check"
	"lmp/server/model/data_collector/dao"
	"lmp/server/model/data_collector/logic"
)

func TestConnectSqlite(t *testing.T) {
	if err := dao.ConnectSqlite(); err != nil {
		t.Error("Connect failed:", err)
	}
}

func TestInitSqlite(t *testing.T) {
	if err := dao.InitSqlite(); err != nil {
		t.Error("first run failed", err)
	}
}

func TestCreatePluginRecord(t *testing.T) {
	_ = dao.InitSqlite()
	var record dao.Indextable
	err := dao.CreatePluginRecord("test")
	if err != nil {
		t.Error("Create record failed:", err)
	} else {
		dao.GLOBALDB.Find(&record)
		fmt.Println(record)
	}
}

func TestDeletePluginRecord(t *testing.T) {
	var column dao.Indextable
	_ = dao.InitSqlite()
	_ = dao.CreatePluginRecord("test")
	err := dao.DeletePluginRecord("test")
	if err != nil {
		t.Error("Delete record failed:", err)
	} else {
		dao.GLOBALDB.Find(&column)
		fmt.Println(column)
	}
}

func TestCreateTable(t *testing.T) {
	ti := dao.TableInfo{TableName: "test3"}
	if err := ti.CreateTable(); err != nil {
		t.Error("Create A Plugin Table failed:", err)
	}
}

func TestAppendTable(t *testing.T) {
	ti := dao.TableInfo{
		TableName: "plugin_test",
	}
	_ = ti.CreateTable()
	if err, _ := ti.AppenTableByData("TIME|TEXT   READ_s|INTEGER WRITE_s|INTEGER FSYNC_s|INTEGER OPEN_s|INTEGER CREATE_s|INTEGER", "21:52:36:      1300       16        0       13        0"); err != nil {
		t.Error("Append plugin table failed:", err)
	}
}

func TestInsertRow(t *testing.T) {
	_ = dao.InitSqlite()
	ti := dao.TableInfo{
		TableName: "plugin_test",
	}
	_ = ti.CreateTable()
	_, ti = ti.AppenTableByData("TIME  READ_s WRITE_s FSYNC_s OPEN_s CREATE_s", "21:52:36:      1300       16        0       13        0")
	line := "21:52:36:      1300       16        0       13        0"
	if err := ti.InsertRow(line); err != nil {
		t.Error("InsertRow failed:", err)
	}
}

func TestDataCollectorIndex(t *testing.T) {
	if err, _ := logic.DataCollectorIndexFromData("test_data_index", "TIME   READ_s WRITE_s FSYNC_s OPEN_s CREATE_s", "21:52:36:      1300       16        0       13        0"); err != nil {
		t.Error("DataCollectorIndex failed:", err)
	}
}

func TestDataCollectorRow(t *testing.T) {
	_, tableinfo := logic.DataCollectorIndexFromData("test_data_index", "TIME  READ_s WRITE_s FSYNC_s OPEN_s CREATE_s", "21:52:36:      1300       16        0       13        0")
	if err := logic.DataCollectorRow(tableinfo, "21:52:36:      1300       16        0       13        0"); err != nil {
		t.Error("Insert row failed:", err)
	}
}

func TestGetTypeFromData(t *testing.T) {
	typeresult := check.GetTypeFromData("0.85")
	fmt.Println(typeresult)
}

func TestIsPossiblyLost(t *testing.T) {
	fmt.Println(check.IsPossiblyLost("Possibly lost 2163 samples"))
}

func TestFindListInfo(t *testing.T) {
	_ = dao.ConnectSqlite()
	list := dao.FindAllRecord()
	fmt.Println(list)
}

func TestJoin(t *testing.T) {
	list := []string{"1", "2"}
	line := strings.Join(list, " ")
	fmt.Println((line))
}
