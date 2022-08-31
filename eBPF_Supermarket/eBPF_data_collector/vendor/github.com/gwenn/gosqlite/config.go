// Copyright 2010 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package sqlite

/*
#include <sqlite3.h>
#include <stdlib.h>

// cgo doesn't support varargs
static inline int my_db_config(sqlite3 *db, int op, int v, int *ok) {
	return sqlite3_db_config(db, op, v, ok);
}

static inline int goSqlite3ConfigThreadMode(int mode) {
	return sqlite3_config(mode);
}

static inline int goSqlite3Config(int op, int mode) {
	return sqlite3_config(op, mode);
}

// Workaround for missing defines in older SQLite
#if SQLITE_VERSION_NUMBER < 3026000
#define SQLITE_DBCONFIG_DEFENSIVE 1010
#endif
#if SQLITE_VERSION_NUMBER < 3031000
#define SQLITE_DBCONFIG_TRUSTED_SCHEMA 1017
#endif
*/
import "C"

import (
	"errors"
	"unsafe"
)

// ThreadingMode enumerates SQLite threading mode
// See ConfigThreadingMode
type ThreadingMode int32

// SQLite threading modes
const (
	SingleThread ThreadingMode = C.SQLITE_CONFIG_SINGLETHREAD
	MultiThread  ThreadingMode = C.SQLITE_CONFIG_MULTITHREAD
	Serialized   ThreadingMode = C.SQLITE_CONFIG_SERIALIZED
)

// ConfigThreadingMode alters threading mode.
// (See sqlite3_config(SQLITE_CONFIG_SINGLETHREAD|SQLITE_CONFIG_MULTITHREAD|SQLITE_CONFIG_SERIALIZED): http://sqlite.org/c3ref/config.html)
func ConfigThreadingMode(mode ThreadingMode) error {
	rv := C.goSqlite3ConfigThreadMode(C.int(mode))
	if rv == C.SQLITE_OK {
		return nil
	}
	return Errno(rv)
}

// ConfigMemStatus enables or disables the collection of memory allocation statistics.
// (See sqlite3_config(SQLITE_CONFIG_MEMSTATUS): http://sqlite.org/c3ref/config.html)
func ConfigMemStatus(b bool) error {
	rv := C.goSqlite3Config(C.SQLITE_CONFIG_MEMSTATUS, btocint(b))
	if rv == C.SQLITE_OK {
		return nil
	}
	return Errno(rv)
}

// ConfigURI enables or disables URI handling.
// (See sqlite3_config(SQLITE_CONFIG_URI): http://sqlite.org/c3ref/config.html)
func ConfigURI(b bool) error {
	rv := C.goSqlite3Config(C.SQLITE_CONFIG_URI, btocint(b))
	if rv == C.SQLITE_OK {
		return nil
	}
	return Errno(rv)
}

// EnableSharedCache enables or disables shared pager cache
// (See http://sqlite.org/c3ref/enable_shared_cache.html)
func EnableSharedCache(b bool) error {
	rv := C.sqlite3_enable_shared_cache(btocint(b))
	if rv == C.SQLITE_OK {
		return nil
	}
	return Errno(rv)
}

/* Database Connection Configuration Options
//   https://www.sqlite.org/c3ref/c_dbconfig_defensive.html
*/

// EnableFKey enables or disables the enforcement of foreign key constraints.
// Calls sqlite3_db_config(db, SQLITE_DBCONFIG_ENABLE_FKEY, b).
// Another way is PRAGMA foreign_keys = boolean;
//
// (See https://www.sqlite.org/c3ref/c_dbconfig_defensive.html#sqlitedbconfigenablefkey)
func (c *Conn) EnableFKey(b bool) (bool, error) {
	return c.queryOrSetEnableDbConfig(C.SQLITE_DBCONFIG_ENABLE_FKEY, btocint(b))
}

// IsFKeyEnabled reports if the enforcement of foreign key constraints is enabled or not.
// Calls sqlite3_db_config(db, SQLITE_DBCONFIG_ENABLE_FKEY, -1).
// Another way is PRAGMA foreign_keys;
//
// (See https://www.sqlite.org/c3ref/c_dbconfig_defensive.html#sqlitedbconfigenablefkey)
func (c *Conn) IsFKeyEnabled() (bool, error) {
	return c.queryOrSetEnableDbConfig(C.SQLITE_DBCONFIG_ENABLE_FKEY, -1)
}

// EnableTriggers enables or disables triggers.
// Calls sqlite3_db_config(db, SQLITE_DBCONFIG_ENABLE_TRIGGER, b).
//
// (See https://www.sqlite.org/c3ref/c_dbconfig_defensive.html#sqlitedbconfigenabletrigger)
func (c *Conn) EnableTriggers(b bool) (bool, error) {
	return c.queryOrSetEnableDbConfig(C.SQLITE_DBCONFIG_ENABLE_TRIGGER, btocint(b))
}

// AreTriggersEnabled checks if triggers are enabled.
// Calls sqlite3_db_config(db, SQLITE_DBCONFIG_ENABLE_TRIGGER, -1)
//
// (See https://www.sqlite.org/c3ref/c_dbconfig_defensive.html#sqlitedbconfigenabletrigger)
func (c *Conn) AreTriggersEnabled() (bool, error) {
	return c.queryOrSetEnableDbConfig(C.SQLITE_DBCONFIG_ENABLE_TRIGGER, -1)
}

// EnableDefensive enables or disables the defensive flag.
// Calls sqlite3_db_config(db, SQLITE_DBCONFIG_DEFENSIVE, b).
//
// (See https://www.sqlite.org/c3ref/c_dbconfig_defensive.html#sqlitedbconfigdefensive)
func (c *Conn) EnableDefensive(b bool) (bool, error) {
	if C.SQLITE_VERSION_NUMBER < 3026000 {
		// SQLITE_DBCONFIG_DEFENSIVE was added in SQLite 3.26.0:
		//   https://github.com/sqlite/sqlite/commit/a296cda016dfcf81674b04c041637fa0a4f426ac
		return false, errors.New("SQLITE_DBCONFIG_DEFENSIVE isn't present in the called SQLite library")
	}
	return c.queryOrSetEnableDbConfig(C.SQLITE_DBCONFIG_DEFENSIVE, btocint(b))
}

// IsDefensiveEnabled reports if the defensive flag is enabled or not.
// Calls sqlite3_db_config(db, SQLITE_DBCONFIG_DEFENSIVE, -1).
//
// (See https://www.sqlite.org/c3ref/c_dbconfig_defensive.html#sqlitedbconfigdefensive)
func (c *Conn) IsDefensiveEnabled() (bool, error) {
	if C.SQLITE_VERSION_NUMBER < 3026000 {
		// SQLITE_DBCONFIG_DEFENSIVE was added in SQLite 3.26.0:
		//   https://github.com/sqlite/sqlite/commit/a296cda016dfcf81674b04c041637fa0a4f426ac
		return false, errors.New("SQLITE_DBCONFIG_DEFENSIVE isn't present in the called SQLite library")
	}
	return c.queryOrSetEnableDbConfig(C.SQLITE_DBCONFIG_DEFENSIVE, -1)
}

// EnableTrustedSchema tells SQLite whether or not to assume that database schemas are untainted by malicious content.
// Calls sqlite3_db_config(db, SQLITE_DBCONFIG_TRUSTED_SCHEMA, b).
// Another way is PRAGMA trusted_schema = boolean;
//
// (See https://sqlite.org/c3ref/c_dbconfig_defensive.html#sqlitedbconfigtrustedschema)
func (c *Conn) EnableTrustedSchema(b bool) (bool, error) {
	if C.SQLITE_VERSION_NUMBER < 3031000 {
		// SQLITE_DBCONFIG_TRUSTED_SCHEMA was added in SQLite 3.31.0:
		//   https://github.com/sqlite/sqlite/commit/b77da374ab6dfeaac5def640da91f219da7fa5c0
		return false, errors.New("SQLITE_DBCONFIG_TRUSTED_SCHEMA isn't present in the called SQLite library")
	}
	return c.queryOrSetEnableDbConfig(C.SQLITE_DBCONFIG_TRUSTED_SCHEMA, btocint(b))
}

// IsTrustedSchema reports whether or not the SQLITE_DBCONFIG_TRUSTED_SCHEMA option is enabled.
// Calls sqlite3_db_config(db, SQLITE_DBCONFIG_TRUSTED_SCHEMA, -1).
// Another way is PRAGMA trusted_schema;
//
// (See https://sqlite.org/c3ref/c_dbconfig_defensive.html#sqlitedbconfigtrustedschema)
func (c *Conn) IsTrustedSchema() (bool, error) {
	if C.SQLITE_VERSION_NUMBER < 3031000 {
		// SQLITE_DBCONFIG_TRUSTED_SCHEMA was added in SQLite 3.31.0:
		//   https://github.com/sqlite/sqlite/commit/b77da374ab6dfeaac5def640da91f219da7fa5c0
		return false, errors.New("SQLITE_DBCONFIG_TRUSTED_SCHEMA isn't present in the called SQLite library")
	}
	return c.queryOrSetEnableDbConfig(C.SQLITE_DBCONFIG_TRUSTED_SCHEMA, -1)
}

func (c *Conn) queryOrSetEnableDbConfig(key, i C.int) (bool, error) {
	var ok C.int
	rv := C.my_db_config(c.db, key, i, &ok)
	if rv == C.SQLITE_OK {
		return ok == 1, nil
	}
	return false, c.error(rv)
}

// EnableExtendedResultCodes enables or disables the extended result codes feature of SQLite.
// (See http://sqlite.org/c3ref/extended_result_codes.html)
func (c *Conn) EnableExtendedResultCodes(b bool) error {
	return c.error(C.sqlite3_extended_result_codes(c.db, btocint(b)), "Conn.EnableExtendedResultCodes")
}

// CompileOptionUsed returns false or true indicating whether the specified option was defined at compile time.
// (See http://sqlite.org/c3ref/compileoption_get.html)
func CompileOptionUsed(optName string) bool {
	cOptName := C.CString(optName)
	defer C.free(unsafe.Pointer(cOptName))
	return C.sqlite3_compileoption_used(cOptName) == 1
}
