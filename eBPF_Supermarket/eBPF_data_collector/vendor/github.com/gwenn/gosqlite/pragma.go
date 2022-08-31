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
	"io"
)

// IntegrityCheck checks database integrity.
// Database name is optional (default is 'main').
// (See http://www.sqlite.org/pragma.html#pragma_integrity_check
// and http://www.sqlite.org/pragma.html#pragma_quick_check)
func (c *Conn) IntegrityCheck(dbName string, max int, quick bool) error {
	var prefix string
	if quick {
		prefix = "quick"
	} else {
		prefix = "integrity"
	}
	pragmaName := fmt.Sprintf("%s_check(%d)", prefix, max)
	var msg string
	err := c.oneValue(pragma(dbName, pragmaName), &msg)
	if err != nil {
		return err
	}
	if msg != "ok" {
		return c.specificError("integrity check failed on %q (%s)", dbName, msg)
	}
	return nil
}

// Encoding returns the text encoding used by the specified database.
// Database name is optional (default is 'main').
// (See http://sqlite.org/pragma.html#pragma_encoding)
func (c *Conn) Encoding(dbName string) (string, error) {
	var encoding string
	err := c.oneValue(pragma(dbName, "encoding"), &encoding)
	if err != nil {
		return "", err
	}
	return encoding, nil
}

// SchemaVersion gets the value of the schema-version.
// Database name is optional (default is 'main').
// (See http://sqlite.org/pragma.html#pragma_schema_version)
func (c *Conn) SchemaVersion(dbName string) (int, error) {
	var version int
	err := c.oneValue(pragma(dbName, "schema_version"), &version)
	if err != nil {
		return -1, err
	}
	return version, nil
}

// SetRecursiveTriggers sets or clears the recursive trigger capability.
// Database name is optional (default is 'main').
// (See http://sqlite.org/pragma.html#pragma_recursive_triggers)
func (c *Conn) SetRecursiveTriggers(dbName string, on bool) error {
	return c.FastExec(pragma(dbName, fmt.Sprintf("recursive_triggers=%t", on)))
}

// JournalMode queries the current journaling mode for database.
// Database name is optional (default is 'main').
// (See http://sqlite.org/pragma.html#pragma_journal_mode)
func (c *Conn) JournalMode(dbName string) (string, error) {
	var mode string
	err := c.oneValue(pragma(dbName, "journal_mode"), &mode)
	if err != nil {
		return "", err
	}
	return mode, nil
}

// SetJournalMode changes the journaling mode for database.
// Database name is optional (default is 'main').
// (See http://sqlite.org/pragma.html#pragma_journal_mode)
func (c *Conn) SetJournalMode(dbName, mode string) (string, error) {
	var newMode string
	err := c.oneValue(pragma(dbName, Mprintf("journal_mode=%Q", mode)), &newMode)
	if err != nil {
		return "", err
	}
	return newMode, nil
}

// LockingMode queries the database connection locking-mode.
// Database name is optional (default is 'main').
// (See http://sqlite.org/pragma.html#pragma_locking_mode)
func (c *Conn) LockingMode(dbName string) (string, error) {
	var mode string
	err := c.oneValue(pragma(dbName, "locking_mode"), &mode)
	if err != nil {
		return "", err
	}
	return mode, nil
}

// SetLockingMode changes the database connection locking-mode.
// Database name is optional (default is 'main').
// (See http://sqlite.org/pragma.html#pragma_locking_mode)
func (c *Conn) SetLockingMode(dbName, mode string) (string, error) {
	var newMode string
	err := c.oneValue(pragma(dbName, Mprintf("locking_mode=%Q", mode)), &newMode)
	if err != nil {
		return "", err
	}
	return newMode, nil
}

// Synchronous queries the synchronous flag.
// Database name is optional (default is 'main').
// (See http://sqlite.org/pragma.html#pragma_synchronous)
func (c *Conn) Synchronous(dbName string) (int, error) {
	var mode int
	err := c.oneValue(pragma(dbName, "synchronous"), &mode)
	if err != nil {
		return -1, err
	}
	return mode, nil
}

// SetSynchronous changes the synchronous flag.
// Database name is optional (default is 'main').
// (See http://sqlite.org/pragma.html#pragma_synchronous)
func (c *Conn) SetSynchronous(dbName string, mode int) error {
	return c.FastExec(pragma(dbName, fmt.Sprintf("synchronous=%d", mode)))
}

// FkViolation is the description of one foreign key constraint violation.
type FkViolation struct {
	Table  string
	RowID  int64
	Parent string
	FkID   int
}

// ForeignKeyCheck checks the database, or the table, for foreign key constraints that are violated
// and returns one row of output for each violation.
// Database name is optional (default is 'main').
// Table name is optional (default is all tables).
// (See http://sqlite.org/pragma.html#pragma_foreign_key_check)
func (c *Conn) ForeignKeyCheck(dbName, table string) ([]FkViolation, error) {
	var pragma string
	if len(dbName) == 0 {
		if len(table) == 0 {
			pragma = "PRAGMA foreign_key_check"
		} else {
			pragma = fmt.Sprintf(`PRAGMA foreign_key_check("%s")`, escapeQuote(table))
		}
	} else {
		if len(table) == 0 {
			pragma = fmt.Sprintf("PRAGMA %s.foreign_key_check", doubleQuote(dbName))
		} else {
			pragma = fmt.Sprintf(`PRAGMA %s.foreign_key_check("%s")`, doubleQuote(dbName), escapeQuote(table))
		}
	}
	s, err := c.prepare(pragma)
	if err != nil {
		return nil, err
	}
	defer s.finalize()
	// table|rowid|parent|fkid
	var violations = make([]FkViolation, 0, 20)
	err = s.execQuery(func(s *Stmt) (err error) {
		v := FkViolation{}
		if err = s.Scan(&v.Table, &v.RowID, &v.Parent, &v.FkID); err != nil {
			return
		}
		violations = append(violations, v)
		return
	})
	if err != nil {
		return nil, err
	}
	return violations, nil
}

// QueryOnly queries the status of the database.
// Database name is optional (default is 'main').
// (See http://sqlite.org/pragma.html#pragma_query_only)
func (c *Conn) QueryOnly(dbName string) (bool, error) {
	var queryOnly bool
	err := c.oneValue(pragma(dbName, "query_only"), &queryOnly)
	if err != nil {
		return false, err
	}
	return queryOnly, nil
}

// SetQueryOnly prevents all changes to database files when enabled.
// Database name is optional (default is 'main').
// (See http://sqlite.org/pragma.html#pragma_query_only)
func (c *Conn) SetQueryOnly(dbName string, mode bool) error {
	return c.FastExec(pragma(dbName, fmt.Sprintf("query_only=%t", mode)))
}

// ApplicationID queries the "Application ID" integer located into the database header.
// Database name is optional (default is 'main').
// (See http://sqlite.org/pragma.html#pragma_application_id)
func (c *Conn) ApplicationID(dbName string) (int, error) {
	var id int
	err := c.oneValue(pragma(dbName, "application_id"), &id)
	if err != nil {
		return -1, err
	}
	return id, nil
}

// SetApplicationID changes the "Application ID".
// Database name is optional (default is 'main').
// (See http://sqlite.org/pragma.html#pragma_application_id)
func (c *Conn) SetApplicationID(dbName string, id int) error {
	return c.FastExec(pragma(dbName, fmt.Sprintf("application_id=%d", id)))
}

// MMapSize queries the maximum number of bytes that are set aside for memory-mapped I/O.
// Database name is optional (default is 'main').
// (See http://www.sqlite.org/pragma.html#pragma_mmap_size and http://sqlite.org/mmap.html)
func (c *Conn) MMapSize(dbName string) (int64, error) {
	var size int64
	err := c.oneValue(pragma(dbName, "mmap_size"), &size)
	if err != nil {
		return -1, err
	}
	return size, nil
}

// SetMMapSize changes the maximum number of bytes that are set aside for memory-mapped I/O.
// Database name is optional (default is 'main').
// If the specified size is zero then memory mapped I/O is disabled.
// If the specified size is negative, then the limit reverts to the default value.
// The size of the memory-mapped I/O region cannot be changed while the memory-mapped I/O region is in active use.
// (See http://www.sqlite.org/pragma.html#pragma_mmap_size and http://sqlite.org/mmap.html)
func (c *Conn) SetMMapSize(dbName string, size int64) (int64, error) {
	var newSize int64
	err := c.oneValue(pragma(dbName, fmt.Sprintf("mmap_size=%d", size)), &newSize)
	if err != nil {
		return -1, err
	}
	return newSize, nil
}

func pragma(dbName, pragmaName string) string {
	if len(dbName) == 0 {
		return "PRAGMA " + pragmaName
	}
	if dbName == "main" || dbName == "temp" {
		return fmt.Sprintf("PRAGMA %s.%s", dbName, pragmaName)
	}
	return fmt.Sprintf("PRAGMA %s.%s", doubleQuote(dbName), pragmaName)
}

func (c *Conn) oneValue(query string, value interface{}) error { // no cache
	s, err := c.prepare(query)
	if err != nil {
		return err
	}
	defer s.finalize()
	rv := C.sqlite3_step(s.stmt)
	err = Errno(rv)
	if err == Row {
		return s.Scan(value)
	} else if err == Done {
		return io.EOF
	}
	return s.error(rv, fmt.Sprintf("Conn.oneValue(%q)", query))
}
func (s *Stmt) execQuery(rowCallbackHandler func(s *Stmt) error) error { // no check on column count
	for {
		if ok, err := s.Next(); err != nil {
			return err
		} else if !ok {
			break
		}
		if err := rowCallbackHandler(s); err != nil {
			return err
		}
	}
	return nil
}
