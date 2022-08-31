// Copyright 2010 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package sqlite

/*
#include <sqlite3.h>
*/
import "C"

// Limit enumerates run-time limit categories
// (See http://www.sqlite.org/c3ref/c_limit_attached.html)
type Limit int32

// Run-time limit categories
const (
	LimitLength            Limit = C.SQLITE_LIMIT_LENGTH     // The maximum size of any string or BLOB or table row, in bytes.
	LimitSQLLength         Limit = C.SQLITE_LIMIT_SQL_LENGTH // The maximum length of a SQL statement, in bytes.
	LimitColumn            Limit = C.SQLITE_LIMIT_COLUMN
	LimitExprDepth         Limit = C.SQLITE_LIMIT_EXPR_DEPTH
	LimitCompoundSelect    Limit = C.SQLITE_LIMIT_COMPOUND_SELECT
	LimitVdbeOp            Limit = C.SQLITE_LIMIT_VDBE_OP
	LimitFunctionArg       Limit = C.SQLITE_LIMIT_FUNCTION_ARG
	LimitAttached          Limit = C.SQLITE_LIMIT_ATTACHED
	LimitLikePatternLength Limit = C.SQLITE_LIMIT_LIKE_PATTERN_LENGTH
	LimitVariableNumber    Limit = C.SQLITE_LIMIT_VARIABLE_NUMBER
	LimitTriggerLength     Limit = C.SQLITE_LIMIT_TRIGGER_DEPTH
)

// Limit queries the current value of a limit.
// (See http://www.sqlite.org/c3ref/limit.html)
func (c *Conn) Limit(id Limit) int32 {
	return int32(C.sqlite3_limit(c.db, C.int(id), -1))
}

// SetLimit changes the value of a limit.
// (See http://www.sqlite.org/c3ref/limit.html)
func (c *Conn) SetLimit(id Limit, newVal int32) int32 {
	return int32(C.sqlite3_limit(c.db, C.int(id), C.int(newVal)))
}
