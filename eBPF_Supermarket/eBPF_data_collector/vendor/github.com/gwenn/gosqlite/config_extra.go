// Copyright 2010 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// +build all
// See SQLITE_OMIT_LOAD_EXTENSION (http://www.sqlite.org/compile.html)

package sqlite

/*
#include <sqlite3.h>
#include <stdlib.h>

static int goSqlite3ConfigMMapSize(sqlite3_int64 defaultSize, sqlite3_int64 maxSize) {
#if SQLITE_VERSION_NUMBER < 3007017
	return -1;
#else
	return sqlite3_config(SQLITE_CONFIG_MMAP_SIZE, defaultSize, maxSize);
#endif
}
*/
import "C"

import (
	"unsafe"
)

// EnableLoadExtension enables or disables extension loading.
// (See http://sqlite.org/c3ref/enable_load_extension.html)
func (c *Conn) EnableLoadExtension(b bool) error {
	rv := C.sqlite3_enable_load_extension(c.db, btocint(b))
	if rv == C.SQLITE_OK {
		return nil
	}
	return c.error(rv, "Conn.EnableLoadExtension")
}

// LoadExtension loads an extension
// (See http://sqlite.org/c3ref/load_extension.html)
func (c *Conn) LoadExtension(file string, proc ...string) error {
	cfile := C.CString(file)
	defer C.free(unsafe.Pointer(cfile))
	var cproc *C.char
	if len(proc) > 0 {
		cproc = C.CString(proc[0])
		defer C.free(unsafe.Pointer(cproc))
	}
	var errMsg *C.char
	rv := C.sqlite3_load_extension(c.db, cfile, cproc, &errMsg)
	if rv != C.SQLITE_OK {
		defer C.sqlite3_free(unsafe.Pointer(errMsg))
		return c.error(rv, C.GoString(errMsg))
	}
	return nil
}

// ConfigMMapSize decreases or increases the default mmap_size/reduces the hard upper bound at start time.
// (See http://www.sqlite.org/c3ref/c_config_covering_index_scan.html#sqliteconfigmmapsize)
func ConfigMMapSize(defaultSize, maxSize int64) error {
	rv := C.goSqlite3ConfigMMapSize(C.sqlite3_int64(defaultSize), C.sqlite3_int64(maxSize))
	if rv == C.SQLITE_OK {
		return nil
	}
	return Errno(rv)
}
