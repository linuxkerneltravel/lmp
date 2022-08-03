package unit_test

import (
	"fmt"
	"lmp/server/model/data_collector"
	"lmp/server/model/data_collector/dao"
	"os/exec"
	"syscall"
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
		t.Error("Delete column failed:", err)
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
	if err := ti.AppendTable("TIME|TEXT   READ_s|INTEGER WRITE_s|INTEGER FSYNC_s|INTEGER OPEN_s|INTEGER CREATE_s|INTEGER"); err != nil {
		t.Error("Append plugin table failed:", err)
	}
}

func TestInsertRow(t *testing.T) {
	_ = dao.InitSqlite()
	ti := dao.TableInfo{
		TableName: "plugin_test",
	}
	_ = ti.CreateTable()
	_ = ti.AppendTable("TIME|TEXT   READ_s|INTEGER WRITE_s|INTEGER FSYNC_s|INTEGER OPEN_s|INTEGER CREATE_s|INTEGER")
	line := "21:52:36:      1300       16        0       13        0"
	if err := ti.InsertRow(line); err != nil {
		t.Error("InsertRow failed:", err)
	}
}
func TestDataCollectorEnter(t *testing.T) {
	path := "/home/yuemeng/lmp/eBPF_Visualization/eBPF_server/testplugin/helloword.py"
	cmd := exec.Command("python3", "-u", path)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	stout, err := cmd.StdoutPipe()
	if err != nil {
		t.Error("stoutpipe error:", err)
	}
	err = cmd.Start()
	if err != nil {
		t.Error("python process start failed:", err)
	}
	err = cmd.Wait()
	if err != nil {
		t.Error("python process run failed:", err)
	}
	go data_collector.DataCollectorEnter("testout", stout)
	if err != nil {
		t.Error("DataCollector Failed:", err)
	}
}
