// Copyright 2010 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package sqlite

/*
#include <sqlite3.h>
#include <stdlib.h>

extern void goXTrace(void *udp, char *sql);
extern void goXProfile(void *udp, char *sql, sqlite3_uint64 nanoseconds);
extern int goXAuth(void *udp, int action, char *arg1, char *arg2, char *dbName, char *triggerName);
extern int goXBusy(void *udp, int count);
extern int goXProgress(void *udp);

// cgo doesn't support varargs
static inline void my_log(int iErrCode, char *msg) {
	sqlite3_log(iErrCode, msg);
}
extern void goXLog(void *udp, int err, char *msg);
static inline int goSqlite3ConfigLog(void *udp) {
	if (udp) {
		return sqlite3_config(SQLITE_CONFIG_LOG, goXLog, udp);
	} else {
		return sqlite3_config(SQLITE_CONFIG_LOG, 0, 0);
	}
}
*/
import "C"

import (
	"fmt"
	"io"
	"time"
	"unsafe"
)

// Tracer is the signature of a trace function.
// See Conn.Trace
type Tracer func(udp interface{}, sql string)

type sqliteTrace struct {
	f   Tracer
	udp interface{}
}

//export goXTrace
func goXTrace(udp unsafe.Pointer, sql *C.char) {
	arg := (*sqliteTrace)(udp)
	arg.f(arg.udp, C.GoString(sql))
}

// Trace registers or clears a trace function.
// Prepared statement placeholders are replaced/logged with their assigned values.
// There can only be a single tracer defined for each database connection.
// Setting a new tracer clears the old one.
// If f is nil, the current tracer is removed.
// Cannot be used with Go >= 1.6 and cgocheck enabled.
// (See sqlite3_trace, http://sqlite.org/c3ref/profile.html)
func (c *Conn) Trace(f Tracer, udp interface{}) {
	if f == nil {
		c.trace = nil
		C.sqlite3_trace(c.db, nil, nil)
		return
	}
	// To make sure it is not gced, keep a reference in the connection.
	c.trace = &sqliteTrace{f, udp}
	C.sqlite3_trace(c.db, (*[0]byte)(C.goXTrace), unsafe.Pointer(c.trace))
}

// Profiler is the signature of a profile function.
// See Conn.Profile
type Profiler func(udp interface{}, sql string, duration time.Duration)

type sqliteProfile struct {
	f   Profiler
	udp interface{}
}

//export goXProfile
func goXProfile(udp unsafe.Pointer, sql *C.char, nanoseconds C.sqlite3_uint64) {
	arg := (*sqliteProfile)(udp)
	arg.f(arg.udp, C.GoString(sql), time.Duration(int64(nanoseconds)))
}

// Profile registers or clears a profile function.
// Prepared statement placeholders are not logged with their assigned values.
// There can only be a single profiler defined for each database connection.
// Setting a new profiler clears the old one.
// If f is nil, the current profiler is removed.
// Cannot be used with Go >= 1.6 and cgocheck enabled.
// (See sqlite3_profile, http://sqlite.org/c3ref/profile.html)
func (c *Conn) Profile(f Profiler, udp interface{}) {
	if f == nil {
		c.profile = nil
		C.sqlite3_profile(c.db, nil, nil)
		return
	}
	// To make sure it is not gced, keep a reference in the connection.
	c.profile = &sqliteProfile{f, udp}
	C.sqlite3_profile(c.db, (*[0]byte)(C.goXProfile), unsafe.Pointer(c.profile))
}

// Auth enumerates Authorizer return codes
type Auth int32

// Authorizer return codes
const (
	AuthOk     Auth = C.SQLITE_OK
	AuthDeny   Auth = C.SQLITE_DENY
	AuthIgnore Auth = C.SQLITE_IGNORE
)

// Action enumerates Authorizer action codes
type Action int32

// Authorizer action codes
const (
	CreateIndex       Action = C.SQLITE_CREATE_INDEX
	CreateTable       Action = C.SQLITE_CREATE_TABLE
	CreateTempIndex   Action = C.SQLITE_CREATE_TEMP_INDEX
	CreateTempTable   Action = C.SQLITE_CREATE_TEMP_TABLE
	CreateTempTrigger Action = C.SQLITE_CREATE_TEMP_TRIGGER
	CreateTempView    Action = C.SQLITE_CREATE_TEMP_VIEW
	CreateTrigger     Action = C.SQLITE_CREATE_TRIGGER
	CreateView        Action = C.SQLITE_CREATE_VIEW
	Delete            Action = C.SQLITE_DELETE
	DropIndex         Action = C.SQLITE_DROP_INDEX
	DropTable         Action = C.SQLITE_DROP_TABLE
	DropTempIndex     Action = C.SQLITE_DROP_TEMP_INDEX
	DropTempTable     Action = C.SQLITE_DROP_TEMP_TABLE
	DropTempTrigger   Action = C.SQLITE_DROP_TEMP_TRIGGER
	DropTempView      Action = C.SQLITE_DROP_TEMP_VIEW
	DropTrigger       Action = C.SQLITE_DROP_TRIGGER
	DropView          Action = C.SQLITE_DROP_VIEW
	Insert            Action = C.SQLITE_INSERT
	Pragma            Action = C.SQLITE_PRAGMA
	Read              Action = C.SQLITE_READ
	Select            Action = C.SQLITE_SELECT
	Transaction       Action = C.SQLITE_TRANSACTION
	Update            Action = C.SQLITE_UPDATE
	Attach            Action = C.SQLITE_ATTACH
	Detach            Action = C.SQLITE_DETACH
	AlterTable        Action = C.SQLITE_ALTER_TABLE
	Reindex           Action = C.SQLITE_REINDEX
	Analyze           Action = C.SQLITE_ANALYZE
	CreateVTable      Action = C.SQLITE_CREATE_VTABLE
	DropVTable        Action = C.SQLITE_DROP_VTABLE
	Function          Action = C.SQLITE_FUNCTION
	Savepoint         Action = C.SQLITE_SAVEPOINT
	Copy              Action = C.SQLITE_COPY
)

func (a Action) String() string {
	switch a {
	case CreateIndex:
		return "CreateIndex"
	case CreateTable:
		return "CreateTable"
	case CreateTempIndex:
		return "CreateTempIndex"
	case CreateTempTable:
		return "CreateTempTable"
	case CreateTempTrigger:
		return "CreateTempTrigger"
	case CreateTempView:
		return "CreateTempView"
	case CreateTrigger:
		return "CreateTrigger"
	case CreateView:
		return "CreateView"
	case Delete:
		return "Delete"
	case DropIndex:
		return "DropIndex"
	case DropTable:
		return "DropTable"
	case DropTempIndex:
		return "DropTempIndex"
	case DropTempTable:
		return "DropTempTable"
	case DropTempTrigger:
		return "DropTempTrigger"
	case DropTempView:
		return "DropTempView"
	case DropTrigger:
		return "DropTrigger"
	case DropView:
		return "DropView"
	case Insert:
		return "Insert"
	case Pragma:
		return "Pragma"
	case Read:
		return "Read"
	case Select:
		return "Select"
	case Transaction:
		return "Transaction"
	case Update:
		return "Update"
	case Attach:
		return "Attach"
	case Detach:
		return "Detach"
	case AlterTable:
		return "AlterTable"
	case Reindex:
		return "Reindex"
	case Analyze:
		return "Analyze"
	case CreateVTable:
		return "CreateVTable"
	case DropVTable:
		return "DropVTable"
	case Function:
		return "Function"
	case Savepoint:
		return "Savepoint"
	case Copy:
		return "Copy"
	}
	return fmt.Sprintf("Unknown Action: %d", a)
}

// Authorizer is the signature of an access authorization function.
// See Conn.SetAuthorizer
type Authorizer func(udp interface{}, action Action, arg1, arg2, dbName, triggerName string) Auth

type sqliteAuthorizer struct {
	f   Authorizer
	udp interface{}
}

//export goXAuth
func goXAuth(udp unsafe.Pointer, action C.int, arg1, arg2, dbName, triggerName *C.char) C.int {
	arg := (*sqliteAuthorizer)(udp)
	result := arg.f(arg.udp, Action(action), C.GoString(arg1), C.GoString(arg2), C.GoString(dbName), C.GoString(triggerName))
	return C.int(result)
}

// SetAuthorizer sets or clears the access authorization function.
// Cannot be used with Go >= 1.6 and cgocheck enabled.
// (See http://sqlite.org/c3ref/set_authorizer.html)
func (c *Conn) SetAuthorizer(f Authorizer, udp interface{}) error {
	if f == nil {
		c.authorizer = nil
		return c.error(C.sqlite3_set_authorizer(c.db, nil, nil), "Conn.SetAuthorizer")
	}
	// To make sure it is not gced, keep a reference in the connection.
	c.authorizer = &sqliteAuthorizer{f, udp}
	return c.error(C.sqlite3_set_authorizer(c.db, (*[0]byte)(C.goXAuth), unsafe.Pointer(c.authorizer)), "Conn.SetAuthorizer")
}

// BusyHandler is the signature of callback to handle SQLITE_BUSY errors.
// Returns true to try again. Returns false to abort.
// See Conn.BusyHandler
type BusyHandler func(udp interface{}, count int) bool

type sqliteBusyHandler struct {
	f   BusyHandler
	udp interface{}
}

//export goXBusy
func goXBusy(udp unsafe.Pointer, count C.int) C.int {
	arg := (*sqliteBusyHandler)(udp)
	result := arg.f(arg.udp, int(count))
	return btocint(result)
}

// BusyHandler registers a callback to handle SQLITE_BUSY errors.
// There can only be a single busy handler defined for each database connection.
// Setting a new busy handler clears any previously set handler.
// If f is nil, the current handler is removed.
// Cannot be used with Go >= 1.6 and cgocheck enabled.
// (See http://sqlite.org/c3ref/busy_handler.html)
func (c *Conn) BusyHandler(f BusyHandler, udp interface{}) error {
	if f == nil {
		c.busyHandler = nil
		return c.error(C.sqlite3_busy_handler(c.db, nil, nil), "<Conn.BusyHandler")
	}
	// To make sure it is not gced, keep a reference in the connection.
	c.busyHandler = &sqliteBusyHandler{f, udp}
	return c.error(C.sqlite3_busy_handler(c.db, (*[0]byte)(C.goXBusy), unsafe.Pointer(c.busyHandler)), "Conn.BusyHandler")
}

// ProgressHandler is the signature of query progress callback.
// Returns true to interrupt.
// For example, to cancel long-running queries.
// See Conn.ProgressHandler
type ProgressHandler func(udp interface{}) (interrupt bool)

type sqliteProgressHandler struct {
	f   ProgressHandler
	udp interface{}
}

//export goXProgress
func goXProgress(udp unsafe.Pointer) C.int {
	arg := (*sqliteProgressHandler)(udp)
	result := arg.f(arg.udp)
	return btocint(result)
}

// ProgressHandler registers or clears a query progress callback.
// The progress callback will be invoked every numOps opcodes.
// Only a single progress handler may be defined at one time per database connection.
// Setting a new progress handler cancels the old one.
// If f is nil, the current handler is removed.
// Cannot be used with Go >= 1.6 and cgocheck enabled.
// (See http://sqlite.org/c3ref/progress_handler.html)
func (c *Conn) ProgressHandler(f ProgressHandler, numOps int32, udp interface{}) {
	if f == nil {
		c.progressHandler = nil
		C.sqlite3_progress_handler(c.db, 0, nil, nil)
		return
	}
	// To make sure it is not gced, keep a reference in the connection.
	c.progressHandler = &sqliteProgressHandler{f, udp}
	C.sqlite3_progress_handler(c.db, C.int(numOps), (*[0]byte)(C.goXProgress), unsafe.Pointer(c.progressHandler))
}

// StmtStatus enumerates status parameters for prepared statements
type StmtStatus int32

// Status counters for prepared statements
const (
	StmtStatusFullScanStep StmtStatus = C.SQLITE_STMTSTATUS_FULLSCAN_STEP
	StmtStatusSort         StmtStatus = C.SQLITE_STMTSTATUS_SORT
	StmtStatusAutoIndex    StmtStatus = C.SQLITE_STMTSTATUS_AUTOINDEX

//	StmtStatusVmStep       StmtStatus = C.SQLITE_STMTSTATUS_VM_STEP
)

// Status returns the value of a status counter for a prepared statement.
// (See http://sqlite.org/c3ref/stmt_status.html)
func (s *Stmt) Status(op StmtStatus, reset bool) int {
	return int(C.sqlite3_stmt_status(s.stmt, C.int(op), btocint(reset)))
}

// MemoryUsed returns the number of bytes of memory currently outstanding (malloced but not freed).
// (See sqlite3_memory_used: http://sqlite.org/c3ref/memory_highwater.html)
func MemoryUsed() int64 {
	return int64(C.sqlite3_memory_used())
}

// MemoryHighwater returns the maximum value of MemoryUsed() since the high-water mark was last reset.
// (See sqlite3_memory_highwater: http://sqlite.org/c3ref/memory_highwater.html)
func MemoryHighwater(reset bool) int64 {
	return int64(C.sqlite3_memory_highwater(btocint(reset)))
}

// SoftHeapLimit returns the limit on heap size.
// (See http://sqlite.org/c3ref/soft_heap_limit64.html)
func SoftHeapLimit() int64 {
	return SetSoftHeapLimit(-1)
}

// SetSoftHeapLimit imposes a limit on heap size.
// (See http://sqlite.org/c3ref/soft_heap_limit64.html)
func SetSoftHeapLimit(n int64) int64 {
	return int64(C.sqlite3_soft_heap_limit64(C.sqlite3_int64(n)))
}

// Complete determines if an SQL statement is complete.
// (See http://sqlite.org/c3ref/complete.html)
func Complete(sql string) (bool, error) {
	cs := C.CString(sql)
	rv := C.sqlite3_complete(cs)
	C.free(unsafe.Pointer(cs))
	if rv == C.SQLITE_NOMEM {
		return false, ErrNoMem
	}
	return rv != 0, nil
}

// Log writes a message into the error log established by ConfigLog method.
// (See http://sqlite.org/c3ref/log.html and http://www.sqlite.org/errlog.html)
//
// Applications can use the sqlite3_log(E,F,..) API to send new messages to the log, if desired, but this is discouraged.
func Log(err /*Errno*/ int32, msg string) {
	cs := C.CString(msg)
	C.my_log(C.int(err), cs)
	C.free(unsafe.Pointer(cs))
}

// Logger is the signature of SQLite logger implementation.
// See ConfigLog
type Logger func(udp interface{}, err error, msg string)

type sqliteLogger struct {
	f   Logger
	udp interface{}
}

//export goXLog
func goXLog(udp unsafe.Pointer, err C.int, msg *C.char) {
	arg := (*sqliteLogger)(udp)
	arg.f(arg.udp, Errno(err), C.GoString(msg))
}

var logger *sqliteLogger

// ConfigLog configures the logger of the SQLite library.
// Only one logger can be registered at a time for the whole program.
// The logger must be threadsafe.
// Cannot be used with Go >= 1.6 and cgocheck enabled when udp is not nil.
// (See sqlite3_config(SQLITE_CONFIG_LOG,...): http://sqlite.org/c3ref/config.html and http://www.sqlite.org/errlog.html)
func ConfigLog(f Logger, udp interface{}) error {
	var rv C.int
	if f == nil {
		logger = nil
		rv = C.goSqlite3ConfigLog(nil)
	} else {
		// To make sure it is not gced, keep a reference.
		logger = &sqliteLogger{f, udp}
		rv = C.goSqlite3ConfigLog(unsafe.Pointer(logger))
	}
	if rv == C.SQLITE_OK {
		return nil
	}
	return Errno(rv)
}

// ExplainQueryPlan outputs the corresponding EXPLAIN QUERY PLAN report to the specified writer
// (See http://sqlite.org/eqp.html)
func (s *Stmt) ExplainQueryPlan(w io.Writer) error {
	sql := s.SQL()
	if len(sql) == 0 {
		return s.specificError("empty statement")
	}
	explain := "EXPLAIN QUERY PLAN " + s.SQL()

	sExplain, err := s.Conn().prepare(explain)
	if err != nil {
		return err
	}
	defer sExplain.finalize()

	var selectid, order, from int
	var detail string
	err = sExplain.execQuery(func(s *Stmt) error {
		if err := s.Scan(&selectid, &order, &from, &detail); err != nil {
			return err
		}
		_, _ = fmt.Fprintf(w, "%d\t%d\t%d\t%s\n", selectid, order, from, detail)
		return nil
	})
	return err
}
