// Copyright 2023 The LMP Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// https://github.com/linuxkerneltravel/lmp/blob/develop/LICENSE
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// author: Gui-Yue
//
// 数据持久化的方式：通过将数据写入数据库实现数据持久化。

package dao

import (
	"fmt"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"log"
	"os"
	"strconv"
)

type Sqlobj struct {
	Tablename string
	db        *gorm.DB
	Data      map[string]interface{}
}

type Basicdata struct {
	ID int `gorm:"primaryKey;unique;column:ID"`
}

// Connectsql 连接数据库
func (s *Sqlobj) Connectsql() {
	currentdir, _ := os.Getwd()
	path := currentdir + "/dao/data.db"
	db, _ := gorm.Open(sqlite.Open(path), &gorm.Config{})
	log.Println("connected.")
	s.db = db
}

// CreateTable 建表
func (s *Sqlobj) CreateTable() {
	deletetable := fmt.Sprintf("drop table if exists %s;", s.Tablename)
	if err := s.db.Exec(deletetable).Error; err != nil {
		log.Fatalf("drop exist table failed.")
	}
	if err := s.db.Table(s.Tablename).AutoMigrate(&Basicdata{}); err != nil {
		log.Fatalf("create table failed.")
	}
}

// AppendTable 扩展表
func (s *Sqlobj) AppendTable() {
	for key, value := range s.Data {
		datatype := "text"
		if strvalue, is_string := value.(string); is_string {
			// shift numerical data to float64
			if _, err := strconv.ParseFloat(strvalue, 64); err == nil {
				datatype = "real"
			}
		}
		addcolumn := fmt.Sprintf("alter table %s add column \"%s\" %s", s.Tablename, key, datatype)
		s.db.Exec(addcolumn)
	}
}

// CreateRow 写入数据
func (s *Sqlobj) CreateRow() {
	s.db.Table(s.Tablename).Create(s.Data)
}
