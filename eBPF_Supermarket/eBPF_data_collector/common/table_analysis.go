package common

import (
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const SplitCharacter = "|"

type TableInfo struct {
	lock        sync.RWMutex
	TableName   string
	Indexes     []string // ordered
	INdexesInfo map[string]string
}

func NewTableInfoByFilename(filePath string) *TableInfo {
	_, fileName := filepath.Split(filePath)
	return &TableInfo{
		TableName: fileName + "_" + time.Now().Format("2006_01_02_15_04_05"),
	}
}

func (t *TableInfo) IndexProcess(indexes string) error {
	t.lock.Lock()
	defer t.lock.Unlock()

	parms := strings.Fields(indexes)
	t.Indexes = make([]string, len(parms))
	t.INdexesInfo = make(map[string]string, len(parms))
	copy(t.Indexes, parms)

	for k, value := range t.Indexes {
		info := strings.Split(value, SplitCharacter)
		t.Indexes[k] = info[0]
		t.INdexesInfo[info[0]] = info[1]
	}

	//fmt.Println(t.Indexes)
	//fmt.Println("\n")
	//
	//for k, v := range t.INdexesInfo {
	//	fmt.Println(k, v)
	//}

	return nil
}

func (i *TableInfo) DataProcess(line string) error {
	parms := strings.Fields(line)
	fmt.Println(parms)

	var columns string
	for _, v := range i.Indexes {
		columns += v + ", "
	}
	columns = columns[:len(columns)-2]

	//fmt.Println(columns)

	//i.SaveData(parms, columns)
	// todo: rediect data to db
	// 1. parse the number of the index
	// 2. save index
	// 3. create table
	// 4. save data to db

	return nil
}
