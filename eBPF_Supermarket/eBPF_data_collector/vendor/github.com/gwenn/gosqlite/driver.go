// Copyright 2010 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package sqlite

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"reflect"
	"time"
)

func init() {
	sql.Register("sqlite3", &impl{open: defaultOpen})
	if os.Getenv("SQLITE_LOG") != "" {
		_ = ConfigLog(func(d interface{}, err error, msg string) {
			log.Printf("%s: %s, %s\n", d, err, msg)
		}, "SQLITE")
	}
	_ = ConfigMemStatus(false)
}

// impl is an adapter to database/sql/driver
// https://golang.org/pkg/database/sql/driver/#Driver
type impl struct {
	open      func(name string) (*Conn, error)
	configure func(*Conn) error
}

// https://golang.org/pkg/database/sql/driver/#Conn
type conn struct {
	c *Conn
}

// https://golang.org/pkg/database/sql/driver/#Stmt
type stmt struct {
	s            *Stmt
	rowsRef      bool // true if there is a rowsImpl associated to this statement that has not been closed.
	pendingClose bool
}

// https://golang.org/pkg/database/sql/driver/#Rows
type rowsImpl struct {
	s           *stmt
	columnNames []string // cache
	ctx         context.Context
}

// https://golang.org/pkg/database/sql/driver/#Result
type result struct {
	id   int64
	rows int64
}

// https://golang.org/pkg/database/sql/driver/#Result
func (r *result) LastInsertId() (int64, error) {
	return r.id, nil
}

// https://golang.org/pkg/database/sql/driver/#Result
func (r *result) RowsAffected() (int64, error) {
	return r.rows, nil
}

// NewDriver creates a new driver with specialized connection creation/configuration.
//   NewDriver(customOpen, nil) // no post-creation hook
//   NewDriver(nil, customConfigure) // default connection creation but specific configuration step
func NewDriver(open func(name string) (*Conn, error), configure func(*Conn) error) driver.Driver {
	if open == nil {
		open = defaultOpen
	}
	return &impl{open: open, configure: configure}
}

var defaultOpen = func(name string) (*Conn, error) {
	// OpenNoMutex == multi-thread mode (http://sqlite.org/compile.html#threadsafe and http://sqlite.org/threadsafe.html)
	c, err := Open(name, OpenURI, OpenNoMutex, OpenReadWrite, OpenCreate)
	if err != nil {
		return nil, err
	}
	c.BusyTimeout(10 * time.Second)
	//c.DefaultTimeLayout = "2006-01-02 15:04:05.999999999"
	c.ScanNumericalAsTime = true
	return c, nil
}

// Open opens a new database connection.
// ":memory:" for memory db,
// "" for temp file db
// https://golang.org/pkg/database/sql/driver/#Driver
func (d *impl) Open(name string) (driver.Conn, error) {
	c, err := d.open(name)
	if err != nil {
		return nil, err
	}
	if d.configure != nil {
		if err = d.configure(c); err != nil {
			_ = c.Close()
			return nil, err
		}
	}
	return &conn{c}, nil
}

// Unwrap gives access to underlying driver connection.
func Unwrap(db *sql.DB) *Conn {
	_, err := db.Exec("unwrap")
	if cerr, ok := err.(ConnError); ok {
		return cerr.c
	}
	return nil
}

// https://golang.org/pkg/database/sql/driver/#Pinger
func (c *conn) Ping(ctx context.Context) error {
	if c.c.IsClosed() {
		return driver.ErrBadConn
	}
	_, err := c.ExecContext(ctx, "PRAGMA schema_verion", []driver.NamedValue{})
	return err
}

// PRAGMA schema_version may be used to detect when the database schema is altered

// https://golang.org/pkg/database/sql/driver/#Conn
func (c *conn) Prepare(_ string) (driver.Stmt, error) {
	panic("use PrepareContext")
}

// https://golang.org/pkg/database/sql/driver/#ConnPrepareContext
func (c *conn) PrepareContext(_ context.Context, query string) (driver.Stmt, error) {
	if c.c.IsClosed() {
		return nil, driver.ErrBadConn
	}
	s, err := c.c.Prepare(query)
	if err != nil {
		return nil, err
	}
	return &stmt{s: s}, nil
}

// https://golang.org/pkg/database/sql/driver/#ExecerContext
func (c *conn) ExecContext(ctx context.Context, query string, args []driver.NamedValue) (driver.Result, error) {
	if c.c.IsClosed() {
		return nil, driver.ErrBadConn
	}
	if ctx.Done() != nil {
		c.c.ProgressHandler(progressHandler, 100, ctx)
		defer c.c.ProgressHandler(nil, 0, nil)
	}
	if len(args) == 0 {
		if query == "unwrap" {
			return nil, ConnError{c: c.c}
		}
		if err := c.c.FastExec(query); err != nil {
			return nil, ctxError(ctx, err)
		}
		return c.c.result(), nil
	}
	for len(query) > 0 {
		s, err := c.c.Prepare(query)
		if err != nil {
			return nil, ctxError(ctx, err)
		} else if s.stmt == nil {
			// this happens for a comment or white-space
			query = s.tail
			continue
		}
		var subargs []driver.NamedValue
		count := s.BindParameterCount()
		if len(s.tail) > 0 && len(args) >= count {
			subargs = args[:count]
			args = args[count:]
		} else {
			subargs = args
		}
		if err = s.bindNamedValue(subargs); err != nil {
			return nil, ctxError(ctx, err)
		}
		err = s.exec()
		if err != nil {
			_ = s.finalize()
			return nil, ctxError(ctx, err)
		}
		if err = s.finalize(); err != nil {
			return nil, ctxError(ctx, err)
		}
		query = s.tail
	}
	return c.c.result(), nil
}

// https://golang.org/pkg/database/sql/driver/#QueryerContext
func (c *conn) QueryContext(ctx context.Context, query string, args []driver.NamedValue) (driver.Rows, error) {
	if c.c.IsClosed() {
		return nil, driver.ErrBadConn
	}
	st, err := c.c.Prepare(query)
	if err != nil {
		return nil, err
	}
	s := &stmt{s: st}
	return s.QueryContext(ctx, args)
}

// https://golang.org/pkg/database/sql/driver/#Conn
func (c *conn) Close() error {
	return c.c.Close()
}

// https://golang.org/pkg/database/sql/driver/#Conn
// Deprecated
func (c *conn) Begin() (driver.Tx, error) {
	if c.c.IsClosed() {
		return nil, driver.ErrBadConn
	}
	if err := c.c.Begin(); err != nil {
		return nil, err
	}
	return c, nil
}

// https://golang.org/pkg/database/sql/driver/#ConnBeginTx
func (c *conn) BeginTx(_ context.Context, opts driver.TxOptions) (driver.Tx, error) {
	if c.c.IsClosed() {
		return nil, driver.ErrBadConn
	}
	if !c.c.GetAutocommit() {
		return nil, errors.New("nested transactions are not supported")
	}
	if err := c.c.SetQueryOnly("", opts.ReadOnly); err != nil {
		return nil, err
	}
	switch sql.IsolationLevel(opts.Isolation) {
	case sql.LevelDefault, sql.LevelSerializable:
		if err := c.c.FastExec("PRAGMA read_uncommitted=0"); err != nil {
			return nil, err
		}
	case sql.LevelReadUncommitted:
		if err := c.c.FastExec("PRAGMA read_uncommitted=1"); err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("isolation level %d is not supported", opts.Isolation)
	}
	return c.Begin()
}

// https://golang.org/pkg/database/sql/driver/#Tx
func (c *conn) Commit() error {
	return c.c.Commit()
}

// https://golang.org/pkg/database/sql/driver/#Tx
func (c *conn) Rollback() error {
	return c.c.Rollback()
}

// https://golang.org/pkg/database/sql/driver/#SessionResetter
func (c *conn) ResetSession(_ context.Context) error {
	// closed or pending transaction or at least one statement busy
	if c.c.IsClosed() || !c.c.GetAutocommit() /*|| c.c.IsBusy()*/ {
		return driver.ErrBadConn
	}
	return nil
}

// https://golang.org/pkg/database/sql/driver/#Validator
func (c *conn) IsValid() bool {
	// closed or pending transaction or at least one statement busy
	return !c.c.IsClosed() /*&& !c.c.GetAutocommit() && !c.c.IsBusy()*/
}

// https://golang.org/pkg/database/sql/driver/#Stmt
func (s *stmt) Close() error {
	if s.rowsRef { // Currently, it never happens because the sql.Stmt doesn't call driver.Stmt in this case
		s.pendingClose = true
		return nil
	}
	return s.s.Finalize()
}

// https://golang.org/pkg/database/sql/driver/#Stmt
func (s *stmt) NumInput() int {
	return s.s.BindParameterCount()
}

// https://golang.org/pkg/database/sql/driver/#Stmt
// Deprecated
func (s *stmt) Exec(_ []driver.Value) (driver.Result, error) {
	panic("Using ExecContext")
}

// https://golang.org/pkg/database/sql/driver/#Stmt
// Deprecated
func (s *stmt) Query(_ []driver.Value) (driver.Rows, error) {
	panic("Use QueryContext")
}

// https://golang.org/pkg/database/sql/driver/#StmtExecContext
func (s *stmt) ExecContext(ctx context.Context, args []driver.NamedValue) (driver.Result, error) {
	if err := s.s.bindNamedValue(args); err != nil {
		return nil, err
	}
	if ctx.Done() != nil {
		s.s.c.ProgressHandler(progressHandler, 100, ctx)
		defer s.s.c.ProgressHandler(nil, 0, nil)
	}
	if err := s.s.exec(); err != nil {
		return nil, ctxError(ctx, err)
	}
	return s.s.c.result(), nil
}

// https://golang.org/pkg/database/sql/driver/#StmtQueryContext
func (s *stmt) QueryContext(ctx context.Context, args []driver.NamedValue) (driver.Rows, error) {
	if s.rowsRef {
		return nil, errors.New("previously returned Rows still not closed")
	}
	if err := s.s.bindNamedValue(args); err != nil {
		return nil, err
	}
	s.rowsRef = true
	if ctx.Done() != nil {
		s.s.c.ProgressHandler(progressHandler, 100, ctx)
	}
	return &rowsImpl{s, nil, ctx}, nil
}

// https://golang.org/pkg/database/sql/driver/#Rows
func (r *rowsImpl) Columns() []string {
	if r.columnNames == nil {
		r.columnNames = r.s.s.ColumnNames()
	}
	return r.columnNames
}

// https://golang.org/pkg/database/sql/driver/#Rows
func (r *rowsImpl) Next(dest []driver.Value) error {
	ok, err := r.s.s.Next()
	if err != nil {
		return ctxError(r.ctx, err)
	}
	if !ok {
		return io.EOF
	}
	for i := range dest {
		dest[i], _ = r.s.s.ScanValue(i)
		/*if !driver.IsScanValue(dest[i]) {
			panic("Invalid type returned by ScanValue")
		}*/
	}
	return nil
}

// https://golang.org/pkg/database/sql/driver/#Rows
func (r *rowsImpl) Close() error {
	if r.ctx.Done() != nil {
		r.s.s.c.ProgressHandler(nil, 0, nil)
	}
	r.s.rowsRef = false
	if r.s.pendingClose {
		return r.s.Close()
	}
	return r.s.s.Reset()
}

// https://golang.org/pkg/database/sql/driver/#RowsNextResultSet
func (r *rowsImpl) HasNextResultSet() bool {
	return len(r.s.s.tail) > 0
}

// https://golang.org/pkg/database/sql/driver/#RowsNextResultSet
func (r *rowsImpl) NextResultSet() error {
	currentStmt := r.s.s
	nextQuery := currentStmt.tail
	var nextStmt *Stmt
	var err error
	for len(nextQuery) > 0 {
		nextStmt, err = currentStmt.c.Prepare(nextQuery)
		if err != nil {
			return err
		} else if nextStmt.stmt == nil {
			// this happens for a comment or white-space
			nextQuery = nextStmt.tail
			continue
		}
		break
	}
	if nextStmt == nil {
		return io.EOF
	}
	// TODO close vs reset ?
	err = currentStmt.Finalize()
	if err != nil {
		return err
	}
	r.s.s = nextStmt
	return nil
}

// https://golang.org/pkg/database/sql/driver/#RowsColumnTypeScanType
func (r *rowsImpl) ColumnTypeScanType(index int) reflect.Type {
	switch r.s.s.ColumnType(index) {
	case Integer:
		return reflect.TypeOf(int64(0))
	case Float:
		return reflect.TypeOf(float64(0))
	case Text:
		return reflect.TypeOf("")
	case Null:
		return reflect.TypeOf(nil)
	case Blob:
		fallthrough
	default:
		return reflect.TypeOf([]byte{})
	}
}

// https://golang.org/pkg/database/sql/driver/#RowsColumnTypeDatabaseTypeName
func (r *rowsImpl) ColumnTypeDatabaseTypeName(index int) string {
	return r.s.s.ColumnDeclaredType(index)
}

func (c *Conn) result() driver.Result {
	// TODO How to know that the last Stmt has done an INSERT? An authorizer?
	id := c.LastInsertRowid()
	// TODO How to know that the last Stmt has done a DELETE/INSERT/UPDATE? An authorizer?
	rows := int64(c.Changes())
	return &result{id, rows} // FIXME RowAffected/noRows
}

func (s *Stmt) bindNamedValue(args []driver.NamedValue) error {
	for _, v := range args {
		if len(v.Name) == 0 {
			if err := s.BindByIndex(v.Ordinal, v.Value); err != nil {
				return err
			}
		} else {
			index, err := s.BindParameterIndex(":" + v.Name) // TODO "$" and "@"
			if err != nil {
				return err
			}
			if err = s.BindByIndex(index, v.Value); err != nil {
				return err
			}
		}
	}
	return nil
}

func progressHandler(p interface{}) bool {
	if ctx, ok := p.(context.Context); ok {
		select {
		case <-ctx.Done():
			// Cancelled
			return true
		default:
			return false
		}
	}
	return false
}

func ctxError(ctx context.Context, err error) error {
	ctxErr := ctx.Err()
	if ctxErr != nil {
		return ctxErr
	}
	return err
}
