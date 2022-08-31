// Copyright 2010 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package sqlite

import (
	"container/list"
	"sync"
)

const (
	defaultCacheSize = 10
)

// Like http://www.sqlite.org/tclsqlite.html#cache
type cache struct {
	m       sync.Mutex
	l       *list.List
	maxSize int // Cache turned off when maxSize <= 0
}

func newCache() *cache {
	return newCacheSize(defaultCacheSize)
}
func newCacheSize(maxSize int) *cache {
	if maxSize <= 0 {
		return &cache{maxSize: maxSize}
	}
	return &cache{l: list.New(), maxSize: maxSize}
}

// To be called in Conn#Prepare
func (c *cache) find(sql string) *Stmt {
	if c.maxSize <= 0 {
		return nil
	}
	c.m.Lock()
	defer c.m.Unlock()
	for e := c.l.Front(); e != nil; e = e.Next() {
		s := e.Value.(*Stmt)
		if s.SQL() == sql { // TODO s.SQL() may have been trimmed by SQLite
			c.l.Remove(e)
			return s
		}
	}
	return nil
}

// To be called in Stmt#Finalize
func (c *cache) release(s *Stmt) error {
	if c.maxSize <= 0 || len(s.tail) > 0 || s.Busy() {
		return s.finalize()
	}
	if err := s.Reset(); err != nil {
		_ = s.finalize()
		return err
	}
	if err := s.ClearBindings(); err != nil {
		_ = s.finalize()
		return nil
	}
	c.m.Lock()
	defer c.m.Unlock()
	c.l.PushFront(s)
	for c.l.Len() > c.maxSize {
		_ = c.l.Remove(c.l.Back()).(*Stmt).finalize()
	}
	return nil
}

// Finalize and free the cached prepared statements
// To be called in Conn#Close
func (c *cache) flush() {
	if c.maxSize <= 0 {
		return
	}
	c.m.Lock()
	defer c.m.Unlock()
	var e, next *list.Element
	for e = c.l.Front(); e != nil; e = next {
		next = e.Next()
		_ = c.l.Remove(e).(*Stmt).finalize()
	}
}

// CacheSize returns (current, max) sizes.
// Prepared statements cache is turned off when max size is 0
func (c *Conn) CacheSize() (current int, max int) {
	if c.stmtCache.maxSize <= 0 {
		return 0, 0
	}
	return c.stmtCache.l.Len(), c.stmtCache.maxSize
}

// SetCacheSize sets the size of prepared statements cache.
// Cache is turned off (and flushed) when size <= 0
func (c *Conn) SetCacheSize(size int) {
	stmtCache := c.stmtCache
	if stmtCache.l == nil && size > 0 {
		stmtCache.l = list.New()
	}
	if size <= 0 {
		stmtCache.flush()
	}
	stmtCache.maxSize = size
}
