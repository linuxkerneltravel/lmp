// Copyright 2010 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package sqlite

/*
#include <sqlite3.h>
#include <stdlib.h>

extern int goSqlite3CreateModule(sqlite3 *db, const char *zName, void *pClientData);
*/
import "C"

import (
	"fmt"
	"reflect"
	"unsafe"
)

type sqliteModule struct {
	c      *Conn
	name   string
	module Module
	vts    map[*sqliteVTab]struct{}
}

type sqliteVTab struct {
	module *sqliteModule
	vTab   VTab
	vtcs   map[*sqliteVTabCursor]struct{}
}

type sqliteVTabCursor struct {
	vTab       *sqliteVTab
	vTabCursor VTabCursor
}

//export goMInit
func goMInit(db, pClientData unsafe.Pointer, argc int, argv **C.char, pzErr **C.char, isCreate int) unsafe.Pointer {
	m := (*sqliteModule)(pClientData)
	if m.c.db != (*C.sqlite3)(db) {
		*pzErr = mPrintf("%s", "Inconsistent db handles")
		return nil
	}
	args := make([]string, argc)
	var A []*C.char
	slice := reflect.SliceHeader{Data: uintptr(unsafe.Pointer(argv)), Len: argc, Cap: argc}
	a := reflect.NewAt(reflect.TypeOf(A), unsafe.Pointer(&slice)).Elem().Interface()
	for i, s := range a.([]*C.char) {
		args[i] = C.GoString(s)
	}
	var vTab VTab
	var err error
	if isCreate == 1 {
		vTab, err = m.module.Create(m.c, args)
	} else {
		vTab, err = m.module.Connect(m.c, args)
	}

	if err != nil {
		*pzErr = mPrintf("%s", err.Error())
		return nil
	}
	vt := &sqliteVTab{m, vTab, nil}
	// prevents 'vt' from being gced
	if m.vts == nil {
		m.vts = make(map[*sqliteVTab]struct{})
	}
	m.vts[vt] = struct{}{}
	*pzErr = nil
	return unsafe.Pointer(vt)
}

//export goVRelease
func goVRelease(pVTab unsafe.Pointer, isDestroy int) *C.char {
	vt := (*sqliteVTab)(pVTab)
	var err error
	if isDestroy == 1 {
		err = vt.vTab.Destroy()
	} else {
		err = vt.vTab.Disconnect()
	}
	if err != nil {
		return mPrintf("%s", err.Error())
	}
	// TODO Check vt.vtcs is empty
	vt.vtcs = nil
	delete(vt.module.vts, vt)
	return nil
}

//export goVOpen
func goVOpen(pVTab unsafe.Pointer, pzErr **C.char) unsafe.Pointer {
	vt := (*sqliteVTab)(pVTab)
	vTabCursor, err := vt.vTab.Open()
	if err != nil {
		*pzErr = mPrintf("%s", err.Error())
		return nil
	}
	// prevents 'vt' from being gced
	vtc := &sqliteVTabCursor{vt, vTabCursor}
	if vt.vtcs == nil {
		vt.vtcs = make(map[*sqliteVTabCursor]struct{})
	}
	vt.vtcs[vtc] = struct{}{}
	*pzErr = nil
	return unsafe.Pointer(vtc)
}

//export goVClose
func goVClose(pCursor unsafe.Pointer) *C.char {
	vtc := (*sqliteVTabCursor)(pCursor)
	err := vtc.vTabCursor.Close()
	if err != nil {
		return mPrintf("%s", err.Error())
	}
	delete(vtc.vTab.vtcs, vtc)
	return nil
}

//export goMDestroy
func goMDestroy(pClientData unsafe.Pointer) {
	m := (*sqliteModule)(pClientData)
	m.module.DestroyModule()
	// TODO Check m.vts is empty
	m.vts = nil
	delete(m.c.modules, m.name)
}

//export goVFilter
func goVFilter(pCursor unsafe.Pointer) *C.char {
	vtc := (*sqliteVTabCursor)(pCursor)
	err := vtc.vTabCursor.Filter()
	if err != nil {
		return mPrintf("%s", err.Error())
	}
	return nil
}

//export goVNext
func goVNext(pCursor unsafe.Pointer) *C.char {
	vtc := (*sqliteVTabCursor)(pCursor)
	err := vtc.vTabCursor.Next()
	if err != nil {
		return mPrintf("%s", err.Error())
	}
	return nil
}

//export goVEof
func goVEof(pCursor unsafe.Pointer) C.int {
	vtc := (*sqliteVTabCursor)(pCursor)
	return btocint(vtc.vTabCursor.EOF())
}

//export goVColumn
func goVColumn(pCursor, cp unsafe.Pointer, col int) *C.char {
	vtc := (*sqliteVTabCursor)(pCursor)
	c := (*Context)(cp)
	err := vtc.vTabCursor.Column(c, col)
	if err != nil {
		return mPrintf("%s", err.Error())
	}
	return nil
}

//export goVRowid
func goVRowid(pCursor unsafe.Pointer, pRowid *C.sqlite3_int64) *C.char {
	vtc := (*sqliteVTabCursor)(pCursor)
	rowid, err := vtc.vTabCursor.Rowid()
	if err != nil {
		return mPrintf("%s", err.Error())
	}
	*pRowid = C.sqlite3_int64(rowid)
	return nil
}

// Module is a "virtual table module", it defines the implementation of a virtual tables.
// (See http://sqlite.org/c3ref/module.html)
type Module interface {
	Create(c *Conn, args []string) (VTab, error)  // See http://sqlite.org/vtab.html#xcreate
	Connect(c *Conn, args []string) (VTab, error) // See http://sqlite.org/vtab.html#xconnect
	DestroyModule()                               // See http://sqlite.org/c3ref/create_module.html
}

// VTab describes a particular instance of the virtual table.
// (See http://sqlite.org/c3ref/vtab.html)
type VTab interface {
	BestIndex( /*sqlite3_index_info**/ ) error // See http://sqlite.org/vtab.html#xbestindex
	Disconnect() error                         // See http://sqlite.org/vtab.html#xdisconnect
	Destroy() error                            // See http://sqlite.org/vtab.html#sqlite3_module.xDestroy
	Open() (VTabCursor, error)                 // See http://sqlite.org/vtab.html#xopen
}

// VTabExtended lists optional/extended functions.
// (See http://sqlite.org/c3ref/vtab.html)
type VTabExtended interface {
	VTab
	Update( /*int argc, sqlite3_value **argv, */ rowid int64) error

	Begin() error
	Sync() error
	Commit() error
	Rollback() error

	//FindFunction(nArg int, name string /*, void (**pxFunc)(sqlite3_context*,int,sqlite3_value**), void **ppArg*/) error
	Rename(newName string) error

	Savepoint(i int) error
	Release(i int) error
	RollbackTo(i int) error
}

// VTabCursor describes cursors that point into the virtual table and are used to loop through the virtual table.
// (See http://sqlite.org/c3ref/vtab_cursor.html)
type VTabCursor interface {
	Close() error                                                                 // See http://sqlite.org/vtab.html#xclose
	Filter( /*idxNum int, idxStr string, int argc, sqlite3_value **argv*/ ) error // See http://sqlite.org/vtab.html#xfilter
	Next() error                                                                  // See http://sqlite.org/vtab.html#xnext
	EOF() bool                                                                    // See http://sqlite.org/vtab.html#xeof
	// col is zero-based so the first column is numbered 0
	Column(c *Context, col int) error // See http://sqlite.org/vtab.html#xcolumn
	Rowid() (int64, error)            // See http://sqlite.org/vtab.html#xrowid
}

// DeclareVTab declares the Schema of a virtual table.
// (See http://sqlite.org/c3ref/declare_vtab.html)
func (c *Conn) DeclareVTab(sql string) error {
	zSQL := C.CString(sql)
	defer C.free(unsafe.Pointer(zSQL))
	return c.error(C.sqlite3_declare_vtab(c.db, zSQL), fmt.Sprintf("Conn.DeclareVTab(%q)", sql))
}

// CreateModule registers a virtual table implementation.
// Cannot be used with Go >= 1.6 and cgocheck enabled.
// (See http://sqlite.org/c3ref/create_module.html)
func (c *Conn) CreateModule(moduleName string, module Module) error {
	mname := C.CString(moduleName)
	defer C.free(unsafe.Pointer(mname))
	// To make sure it is not gced, keep a reference in the connection.
	udm := &sqliteModule{c, moduleName, module, nil}
	if len(c.modules) == 0 {
		c.modules = make(map[string]*sqliteModule)
	}
	c.modules[moduleName] = udm // FIXME What happens if different modules are registered with the same name?
	return c.error(C.goSqlite3CreateModule(c.db, mname, unsafe.Pointer(udm)),
		fmt.Sprintf("Conn.CreateModule(%q)", moduleName))
}

/*
GO                                                   C
CreateModule(                       int sqlite3_create_module_v2(
 |- c *Conn                          |- sqlite3 *db
 |- moduleName string                |- const char *zName
 |- goModule                         |- const sqlite3_module *p (~) Methods for the module
 |- *sqliteModule                    |- void *pClientData () Client data for xCreate/xConnect
 \- goVDestroy                       \- void(*xDestroy)(void*) () Client data destructor function
)                                   )

goModule                            sqlite3_module {
                                     |- int iVersion
goMInit                              |- int (*xCreate)(sqlite3*, void *pAux, int argc, char **argv, sqlite3_vtab **ppVTab,
                                             char **pzErr)
goMInit                              |- int (*xConnect)(sqlite3*, void *pAux, int argc, char **argv, sqlite3_vtab **ppVTab,
                                             char **pzErr)
x                                    |- int (*xBestIndex)(sqlite3_vtab *pVTab, sqlite3_index_info*)
goVRelease                           |- int (*xDisconnect)(sqlite3_vtab *pVTab)
goVRelease                           |- int (*xDestroy)(sqlite3_vtab *pVTab)
goVOpen                              |- int (*xOpen)(sqlite3_vtab *pVTab, sqlite3_vtab_cursor **ppCursor)
goVClose                             |- int (*xClose)(sqlite3_vtab_cursor*)
x                                    |- int (*xFilter)(sqlite3_vtab_cursor*, int idxNum, const char *idxStr, int argc,
                                             sqlite3_value **argv)
x                                    |- int (*xNext)(sqlite3_vtab_cursor*)
x                                    |- int (*xEof)(sqlite3_vtab_cursor*)
x                                    |- int (*xColumn)(sqlite3_vtab_cursor*, sqlite3_context*, int)
x                                    |- int (*xRowid)(sqlite3_vtab_cursor*, sqlite_int64 *pRowid)
o                                    |- int (*xUpdate)(sqlite3_vtab *, int, sqlite3_value **, sqlite_int64 *)
o                                    |- int (*xBegin)(sqlite3_vtab *pVTab)
o                                    |- int (*xSync)(sqlite3_vtab *pVTab)
o                                    |- int (*xCommit)(sqlite3_vtab *pVTab)
o                                    |- int (*xRollback)(sqlite3_vtab *pVTab)
o                                    |- int (*xFindFunction)(sqlite3_vtab *pVtab, int nArg, const char *zName,
                                             void (**pxFunc)(sqlite3_context*,int,sqlite3_value**), void **ppArg)
x                                    |- int (*xRename)(sqlite3_vtab *pVtab, const char *zNew)
o                                    |- int (*xSavepoint)(sqlite3_vtab *pVTab, int)
o                                    |- int (*xRelease)(sqlite3_vtab *pVTab, int)
o                                    \- int (*xRollbackTo)(sqlite3_vtab *pVTab, int)
                                    }

DeclareVTab                         int sqlite3_declare_vtab( (Called in xCreate/xConnect)
                                     |- sqlite3 *db,
                                     \- const char *zCreateTable
                                    )

sqliteVTab                          sqlite3_vtab { (Created by xCreate/xConnect)
                                     |- const sqlite3_module *pModule
                                     |- int nRef
                                     |- char *zErrMsg
                                     \- ...
                                    }

sqliteVTabCursor                    sqlite3_vtab_cursor { (Created by xOpen)
                                     |- sqlite3_vtab *pVtab
                                     \- ...
                                    }

*/
