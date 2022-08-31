// Copyright 2010 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// +build all
// See SQLITE_ENABLE_COLUMN_METADATA (http://www.sqlite.org/compile.html)

package sqlite

/*
#include <sqlite3.h>
#include <stdlib.h>
*/
import "C"

import (
	"fmt"
	"unsafe"
)

// Column extracts metadata about a column of a table (doesn't work with view).
// Column.Cid and Column.DfltValue are left unspecified.
// (See http://sqlite.org/c3ref/table_column_metadata.html)
func (c *Conn) Column(dbName, tableName, columnName string) (*Column, error) {
	var zDbName *C.char
	if len(dbName) > 0 {
		zDbName = C.CString(dbName)
		defer C.free(unsafe.Pointer(zDbName))
	}
	zTableName := C.CString(tableName)
	defer C.free(unsafe.Pointer(zTableName))
	zColumnName := C.CString(columnName)
	defer C.free(unsafe.Pointer(zColumnName))
	var zDataType, zCollSeq *C.char
	var notNull, primaryKey, autoinc C.int
	rv := C.sqlite3_table_column_metadata(c.db, zDbName, zTableName, zColumnName, &zDataType, &zCollSeq,
		&notNull, &primaryKey, &autoinc)
	if rv != C.SQLITE_OK {
		return nil, c.error(rv, fmt.Sprintf("Conn.Column(db: %q, tbl: %q, col: %q)", dbName, tableName, columnName))
	}
	return &Column{-1, columnName, C.GoString(zDataType), notNull != 0, "", int(primaryKey),
		autoinc != 0, C.GoString(zCollSeq)}, nil
}

// ColumnDatabaseName returns the database
// that is the origin of a particular result column in SELECT statement.
// The left-most column is column 0.
// (See http://www.sqlite.org/c3ref/column_database_name.html)
func (s *Stmt) ColumnDatabaseName(index int) string {
	if index < 0 || index >= s.ColumnCount() {
		panic(fmt.Sprintf("column index %d out of range [0,%d[.", index, s.ColumnCount()))
	}
	return C.GoString(C.sqlite3_column_database_name(s.stmt, C.int(index)))
}

// ColumnTableName returns the original un-aliased table name
// that is the origin of a particular result column in SELECT statement.
// The left-most column is column 0.
// (See http://www.sqlite.org/c3ref/column_database_name.html)
func (s *Stmt) ColumnTableName(index int) string {
	if index < 0 || index >= s.ColumnCount() {
		panic(fmt.Sprintf("column index %d out of range [0,%d[.", index, s.ColumnCount()))
	}
	return C.GoString(C.sqlite3_column_table_name(s.stmt, C.int(index)))
}

// ColumnOriginName returns the original un-aliased table column name
// that is the origin of a particular result column in SELECT statement.
// The left-most column is column 0.
// (See http://www.sqlite.org/c3ref/column_database_name.html)
func (s *Stmt) ColumnOriginName(index int) string {
	if index < 0 || index >= s.ColumnCount() {
		panic(fmt.Sprintf("column index %d out of range [0,%d[.", index, s.ColumnCount()))
	}
	return C.GoString(C.sqlite3_column_origin_name(s.stmt, C.int(index)))
}
