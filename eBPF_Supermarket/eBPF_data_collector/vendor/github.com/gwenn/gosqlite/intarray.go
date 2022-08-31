// Copyright 2010 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package sqlite

/*
#include <sqlite3.h>
#include <stdlib.h>

// An sqlite3_intarray is an abstract type to stores an instance of an integer array.
typedef struct sqlite3_intarray sqlite3_intarray;
extern int sqlite3_intarray_bind(sqlite3_intarray *pIntArray, int nElements, sqlite3_int64 *aElements, void (*xFree)(void*));
extern int sqlite3_intarray_create(sqlite3 *db, const char *zName, sqlite3_intarray **ppReturn);
*/
import "C"

import (
	"errors"
	"fmt"
	"unsafe"
)

// IntArray is the Go-language interface definition for the "intarray" or
// integer array virtual table for SQLite.
//
// The intarray virtual table is designed to facilitate using an
// array of integers as the right-hand side of an IN operator. So
// instead of doing a prepared statement like this:
//
//	SELECT * FROM table WHERE x IN (?,?,?,...,?);
//
// And then binding indivdual integers to each of ? slots, a Go-language
// application can create an intarray object (named "ex1" in the following
// example), prepare a statement like this:
//
//	SELECT * FROM table WHERE x IN ex1;
//
// Then bind an ordinary Go slice of integer values to the ex1 object
// to run the statement.
//
// USAGE:
//
// One or more intarray objects can be created as follows:
//
//	var p1, p2, p3 IntArray
//	p1, err = db.CreateIntArray("ex1")
//	p2, err = db.CreateIntArray("ex2")
//	p3, err = db.CreateIntArray("ex3")
//
// Each call to CreateIntArray() generates a new virtual table
// module and a singleton of that virtual table module in the TEMP
// database.  Both the module and the virtual table instance use the
// name given by the second parameter.  The virtual tables can then be
// used in prepared statements:
//
//	SELECT * FROM t1, t2, t3
//	 WHERE t1.x IN ex1
//	  AND t2.y IN ex2
//	  AND t3.z IN ex3;
//
// Each integer array is initially empty.  New arrays can be bound to
// an integer array as follows:
//
//	p1.Bind([]int64{ 1, 2, 3, 4 })
//	p2.Bind([]int64{ 5, 6, 7, 8, 9, 10, 11 })
//	a3 := make([]int64, 100)
//	// Fill in content of a3
//	p3.Bind(a3)
//
// A single intarray object can be rebound multiple times.  But do not
// attempt to change the bindings of an intarray while it is in the middle
// of a query.
//
// The application must not change the intarray values while an intarray is in
// the middle of a query.
//
// The intarray object is automatically destroyed when its corresponding
// virtual table is dropped.  Since the virtual tables are created in the
// TEMP database, they are automatically dropped when the database connection
// closes so the application does not normally need to take any special
// action to free the intarray objects (except if connections are pooled...).
type IntArray interface {
	Bind(elements []int64)
	Drop() error
}

type intArray struct {
	c       *Conn
	ia      *C.sqlite3_intarray
	name    string
	content []int64
}

// CreateIntArray create a specific instance of an intarray object.
//
// Each intarray object corresponds to a virtual table in the TEMP database
// with the specified name.
//
// Destroy the intarray object by dropping the virtual table.  If not done
// explicitly by the application, the virtual table will be dropped implicitly
// by the system when the database connection is closed.
func (c *Conn) CreateIntArray(name string) (IntArray, error) {
	var ia *C.sqlite3_intarray
	cname := C.CString(name)
	rv := C.sqlite3_intarray_create(c.db, cname, &ia)
	C.free(unsafe.Pointer(cname))
	if rv != C.SQLITE_OK {
		return nil, Errno(rv)
	}
	if ia == nil {
		return nil, errors.New("sqlite succeeded without returning an intarray")
	}
	module := &intArray{c: c, ia: ia, name: name}
	return module, nil
}

// Bind a new array of integers to a specific intarray object.
//
// The array of integers bound must be unchanged for the duration of
// any query against the corresponding virtual table.  If the integer
// array does change or is deallocated undefined behavior will result.
func (m *intArray) Bind(elements []int64) {
	if m.ia == nil {
		return
	}
	m.content = elements
	var p *int64
	if len(elements) > 0 {
		p = &elements[0]
	}
	C.sqlite3_intarray_bind(m.ia, C.int(len(elements)), (*C.sqlite3_int64)(unsafe.Pointer(p)), nil)
}

// Drop underlying virtual table.
func (m *intArray) Drop() error {
	if m == nil {
		return errors.New("nil sqlite intarray")
	}
	if m.c == nil {
		return nil
	}
	err := m.c.FastExec(fmt.Sprintf(`DROP TABLE temp."%s"`, escapeQuote(m.name)))
	if err != nil {
		return err
	}
	m.c = nil
	m.ia = nil
	return nil
}
