// Copyright 2010 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package sqlite

/*
#include <sqlite3.h>
*/
import "C"

import (
	"fmt"
	"strings"
)

// Databases returns one couple (name, file) for each database attached to the current database connection.
// (See http://www.sqlite.org/pragma.html#pragma_database_list)
func (c *Conn) Databases() (map[string]string, error) {
	s, err := c.prepare("PRAGMA database_list")
	if err != nil {
		return nil, err
	}
	defer s.finalize()
	var databases = make(map[string]string)
	var name, file string
	err = s.execQuery(func(s *Stmt) (err error) {
		if err = s.Scan(nil, &name, &file); err != nil {
			return
		}
		databases[name] = file
		return
	})
	if err != nil {
		return nil, err
	}
	return databases, nil
}

// Tables returns tables (no view) from 'sqlite_master'/'sqlite_temp_master' and filters system tables out.
// The database name can be empty, "main", "temp" or the name of an attached database.
func (c *Conn) Tables(dbName string) ([]string, error) {
	var sql string
	if len(dbName) == 0 {
		sql = "SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%' ORDER BY 1"
	} else if strings.EqualFold("temp", dbName) {
		sql = "SELECT name FROM sqlite_temp_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%' ORDER BY 1"
	} else {
		sql = fmt.Sprintf("SELECT name FROM %s.sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%%' ORDER BY 1", doubleQuote(dbName))
	}
	s, err := c.prepare(sql)
	if err != nil {
		return nil, err
	}
	defer s.finalize()
	var tables = make([]string, 0, 20)
	err = s.Select(func(s *Stmt) error {
		name, _ := s.ScanText(0)
		tables = append(tables, name)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return tables, nil
}

// Views returns views from 'sqlite_master'/'sqlite_temp_master'.
// The database name can be empty, "main", "temp" or the name of an attached database.
func (c *Conn) Views(dbName string) ([]string, error) {
	var sql string
	if len(dbName) == 0 {
		sql = "SELECT name FROM sqlite_master WHERE type = 'view' ORDER BY 1"
	} else if strings.EqualFold("temp", dbName) {
		sql = "SELECT name FROM sqlite_temp_master WHERE type = 'view' ORDER BY 1"
	} else {
		sql = fmt.Sprintf("SELECT name FROM %s.sqlite_master WHERE type = 'view' ORDER BY 1", doubleQuote(dbName))
	}
	s, err := c.prepare(sql)
	if err != nil {
		return nil, err
	}
	defer s.finalize()
	var views = make([]string, 0, 20)
	err = s.Select(func(s *Stmt) error {
		name, _ := s.ScanText(0)
		views = append(views, name)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return views, nil
}

// Indexes returns indexes from 'sqlite_master'/'sqlite_temp_master'.
// As the index name is unique by database, (index name, table name) couples are returned.
// The database name can be empty, "main", "temp" or the name of an attached database.
func (c *Conn) Indexes(dbName string) (map[string]string, error) {
	var sql string
	if len(dbName) == 0 {
		sql = "SELECT name, tbl_name FROM sqlite_master WHERE type = 'index'"
	} else if strings.EqualFold("temp", dbName) {
		sql = "SELECT name, tbl_name FROM sqlite_temp_master WHERE type = 'index'"
	} else {
		sql = fmt.Sprintf("SELECT name, tbl_name FROM %s.sqlite_master WHERE type = 'index'", doubleQuote(dbName))
	}
	s, err := c.prepare(sql)
	if err != nil {
		return nil, err
	}
	defer s.finalize()
	var indexes = make(map[string]string)
	var name, table string
	err = s.Select(func(s *Stmt) (err error) {
		s.Scan(&name, &table)
		indexes[name] = table
		return
	})
	if err != nil {
		return nil, err
	}
	return indexes, nil
}

// Column is the description of one table's column
// See Conn.Columns/IndexColumns
type Column struct {
	Cid       int
	Name      string
	DataType  string
	NotNull   bool
	DfltValue string // FIXME type ?
	Pk        int
	Autoinc   bool
	CollSeq   string
}

// Columns returns a description for each column in the named table/view.
// Column.Autoinc and Column.CollSeq are left unspecified.
// No error is returned if the table does not exist.
// (See http://www.sqlite.org/pragma.html#pragma_table_info)
func (c *Conn) Columns(dbName, table string) ([]Column, error) {
	var pragma string
	if len(dbName) == 0 {
		pragma = fmt.Sprintf(`PRAGMA table_info("%s")`, escapeQuote(table))
	} else {
		pragma = fmt.Sprintf(`PRAGMA %s.table_info("%s")`, doubleQuote(dbName), escapeQuote(table))
	}
	s, err := c.prepare(pragma)
	if err != nil {
		return nil, err
	}
	defer s.finalize()
	var columns = make([]Column, 0, 20)
	err = s.execQuery(func(s *Stmt) (err error) {
		c := Column{}
		if err = s.Scan(&c.Cid, &c.Name, &c.DataType, &c.NotNull, &c.DfltValue, &c.Pk); err != nil {
			return
		}
		columns = append(columns, c)
		return
	})
	if err != nil {
		return nil, err
	}
	return columns, nil
}

// ColumnDeclaredType returns the declared type of the table column of a particular result column in SELECT statement.
// If the result column is an expression or subquery, then an empty string is returned.
// The left-most column is column 0.
// (See http://www.sqlite.org/c3ref/column_decltype.html)
func (s *Stmt) ColumnDeclaredType(index int) string {
	if index < 0 || index >= s.ColumnCount() {
		panic(fmt.Sprintf("column index %d out of range [0,%d[.", index, s.ColumnCount()))
	}
	return C.GoString(C.sqlite3_column_decltype(s.stmt, C.int(index)))
}

// Affinity enumerates SQLite column type affinity
type Affinity string

// SQLite column type affinities
const (
	Integral  = Affinity("INTEGER") // Integer affinity
	Real      = Affinity("REAL")
	Numerical = Affinity("NUMERIC")
	None      = Affinity("NONE")
	Textual   = Affinity("TEXT")
)

// ColumnTypeAffinity returns the type affinity of the table column of a particular result column in SELECT statement.
// If the result column is an expression or subquery, then None is returned.
// The left-most column is column 0.
// (See http://sqlite.org/datatype3.html)
func (s *Stmt) ColumnTypeAffinity(index int) Affinity {
	if index < 0 || index >= s.ColumnCount() {
		panic(fmt.Sprintf("column index %d out of range [0,%d[.", index, s.ColumnCount()))
	}
	if s.affinities == nil {
		count := s.ColumnCount()
		s.affinities = make([]Affinity, count)
	} else {
		if affinity := s.affinities[index]; affinity != "" {
			return affinity
		}
	}
	declType := s.ColumnDeclaredType(index)
	affinity := typeAffinity(declType)
	s.affinities[index] = affinity
	return affinity
}

// Affinity returns the type affinity of the column.
func (c Column) Affinity() Affinity {
	return typeAffinity(c.DataType)
}

func typeAffinity(declType string) Affinity {
	if declType == "" {
		return None
	}
	declType = strings.ToUpper(declType)
	if strings.Contains(declType, "INT") {
		return Integral
	} else if strings.Contains(declType, "TEXT") || strings.Contains(declType, "CHAR") || strings.Contains(declType, "CLOB") {
		return Textual
	} else if strings.Contains(declType, "BLOB") {
		return None
	} else if strings.Contains(declType, "REAL") || strings.Contains(declType, "FLOA") || strings.Contains(declType, "DOUB") {
		return Real
	}
	return Numerical
}

// ForeignKey is the description of one table's foreign key
// See Conn.ForeignKeys
type ForeignKey struct {
	Table string
	From  []string
	To    []string
}

// ForeignKeys returns one description for each foreign key that references a column in the argument table.
// No error is returned if the table does not exist.
// (See http://www.sqlite.org/pragma.html#pragma_foreign_key_list)
func (c *Conn) ForeignKeys(dbName, table string) (map[int]*ForeignKey, error) {
	var pragma string
	if len(dbName) == 0 {
		pragma = fmt.Sprintf(`PRAGMA foreign_key_list("%s")`, escapeQuote(table))
	} else {
		pragma = fmt.Sprintf(`PRAGMA %s.foreign_key_list("%s")`, doubleQuote(dbName), escapeQuote(table))
	}
	s, err := c.prepare(pragma)
	if err != nil {
		return nil, err
	}
	defer s.finalize()
	var fks = make(map[int]*ForeignKey)
	var id, seq int
	var ref, from, to string
	err = s.execQuery(func(s *Stmt) (err error) {
		if err = s.NamedScan("id", &id, "seq", &seq, "table", &ref, "from", &from, "to", &to); err != nil {
			return
		}
		fk, ex := fks[id]
		if !ex {
			fk = &ForeignKey{Table: ref}
			fks[id] = fk
		}
		// TODO Ensure columns are appended in the correct order...
		fk.From = append(fk.From, from)
		fk.To = append(fk.To, to)
		return
	})
	if err != nil {
		return nil, err
	}
	return fks, nil
}

// Index is the description of one table's index
// See Conn.Indexes
type Index struct {
	Name   string
	Unique bool
}

// TableIndexes returns one description for each index associated with the given table.
// No error is returned if the table does not exist.
// (See http://www.sqlite.org/pragma.html#pragma_index_list)
func (c *Conn) TableIndexes(dbName, table string) ([]Index, error) {
	var pragma string
	if len(dbName) == 0 {
		pragma = fmt.Sprintf(`PRAGMA index_list("%s")`, escapeQuote(table))
	} else {
		pragma = fmt.Sprintf(`PRAGMA %s.index_list("%s")`, doubleQuote(dbName), escapeQuote(table))
	}
	s, err := c.prepare(pragma)
	if err != nil {
		return nil, err
	}
	defer s.finalize()
	var indexes = make([]Index, 0, 5)
	err = s.execQuery(func(s *Stmt) (err error) {
		i := Index{}
		if _, err = s.ScanByIndex(1, &i.Name); err != nil {
			return
		}
		if _, err = s.ScanByIndex(2, &i.Unique); err != nil {
			return
		}
		indexes = append(indexes, i)
		return
	})
	if err != nil {
		return nil, err
	}
	return indexes, nil
}

// IndexColumns returns one description for each column in the named index.
// Only Column.Cid and Column.Name are specified. All other fields are unspecified.
// No error is returned if the index does not exist.
// (See http://www.sqlite.org/pragma.html#pragma_index_info)
func (c *Conn) IndexColumns(dbName, index string) ([]Column, error) {
	var pragma string
	if len(dbName) == 0 {
		pragma = fmt.Sprintf(`PRAGMA index_info("%s")`, escapeQuote(index))
	} else {
		pragma = fmt.Sprintf(`PRAGMA %s.index_info("%s")`, doubleQuote(dbName), escapeQuote(index))
	}
	s, err := c.prepare(pragma)
	if err != nil {
		return nil, err
	}
	defer s.finalize()
	var columns = make([]Column, 0, 5)
	err = s.execQuery(func(s *Stmt) (err error) {
		c := Column{}
		if err = s.Scan(nil, &c.Cid, &c.Name); err != nil {
			return
		}
		columns = append(columns, c)
		return
	})
	if err != nil {
		return nil, err
	}
	return columns, nil
}
