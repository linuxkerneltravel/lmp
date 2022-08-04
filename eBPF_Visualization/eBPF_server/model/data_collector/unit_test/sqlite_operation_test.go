package unit_test

import (
	"fmt"
	"lmp/server/model/data_collector/dao"
	"lmp/server/model/data_collector/logic"
	"testing"
)

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
	if err, _ := ti.AppendTable("TIME|TEXT   READ_s|INTEGER WRITE_s|INTEGER FSYNC_s|INTEGER OPEN_s|INTEGER CREATE_s|INTEGER"); err != nil {
		t.Error("Append plugin table failed:", err)
	}
}

func TestInsertRow(t *testing.T) {
	_ = dao.InitSqlite()
	ti := dao.TableInfo{
		TableName: "plugin_test",
	}
	_ = ti.CreateTable()
	_, _ = ti.AppendTable("TIME|TEXT   READ_s|INTEGER WRITE_s|INTEGER FSYNC_s|INTEGER OPEN_s|INTEGER CREATE_s|INTEGER")
	line := "21:52:36:      1300       16        0       13        0"
	if err := ti.InsertRow(line); err != nil {
		t.Error("InsertRow failed:", err)
	}
}

func TestDataCollectorIndex(t *testing.T) {
	if err, _ := logic.DataCollectorIndex("test_data_index", "TIME|TEXT   READ_s|INTEGER WRITE_s|INTEGER FSYNC_s|INTEGER OPEN_s|INTEGER CREATE_s|INTEGER"); err != nil {
		t.Error("DataCollectorIndex failed:", err)
	}
}

func TestDataCollectorRow(t *testing.T) {
	_, tableinfo := logic.DataCollectorIndex("test_data_index", "TIME|TEXT   READ_s|INTEGER WRITE_s|INTEGER FSYNC_s|INTEGER OPEN_s|INTEGER CREATE_s|INTEGER")
	if err := logic.DataCollectorRow(tableinfo, "21:52:36:      1300       16        0       13        0"); err != nil {
		t.Error("Insert row failed:", err)
	}
}
