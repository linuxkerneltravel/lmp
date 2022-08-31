// Copyright 2010 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package sqlite

/*
#include <sqlite3.h>
#include <stdlib.h>

// cgo doesn't support varargs
static inline char *my_mprintf(char *zFormat, char *arg) {
	return sqlite3_mprintf(zFormat, arg);
}
*/
import "C"

import (
	"fmt"
	"reflect"
	"strings"
	"unsafe"
)

// Mprintf is like fmt.Printf but implements some additional formatting options
// that are useful for constructing SQL statements.
// (See http://sqlite.org/c3ref/mprintf.html)
func Mprintf(format string, arg string) string {
	zSQL := mPrintf(format, arg)
	defer C.sqlite3_free(unsafe.Pointer(zSQL))
	return C.GoString(zSQL)
}
func mPrintf(format, arg string) *C.char { // TODO may return nil when no memory...
	cf := C.CString(format)
	defer C.free(unsafe.Pointer(cf))
	ca := C.CString(arg)
	defer C.free(unsafe.Pointer(ca))
	return C.my_mprintf(cf, ca)
}

func btocint(b bool) C.int {
	if b {
		return 1
	}
	return 0
}
func cstring(s string) (*C.char, C.int) {
	cs := (*reflect.StringHeader)(unsafe.Pointer(&s))
	return (*C.char)(unsafe.Pointer(cs.Data)), C.int(cs.Len)
}

/*
func gostring(cs *C.char) string {
	var x reflect.StringHeader
	x.Data = uintptr(unsafe.Pointer(cs))
	x.Len = int(C.strlen(cs))
	return *(*string)(unsafe.Pointer(&x))
}
*/

func escapeQuote(identifier string) string {
	if strings.ContainsRune(identifier, '"') { // escape quote by doubling them
		identifier = strings.Replace(identifier, `"`, `""`, -1)
	}
	return identifier
}
func doubleQuote(dbName string) string {
	if dbName == "main" || dbName == "temp" {
		return dbName
	}
	return fmt.Sprintf(`"%s"`, escapeQuote(dbName)) // surround identifier with quote
}
