// Copyright 2010 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// +build all

package sqlite

import (
	"sync"
	"time"
)

// Pool adapted from https://code.google.com/p/vitess/source/browse/go/pools/roundrobin.go
type Pool struct {
	mu          sync.Mutex
	available   *sync.Cond
	conns       chan *Conn
	size        int
	factory     ConnOpen
	idleTimeout time.Duration
}

// ConnOpen is the signature of connection factory.
type ConnOpen func() (*Conn, error)

// NewPool creates a connection pool.
// factory will be the function used to create connections.
// capacity is the maximum number of connections created.
// If a connection is unused beyond idleTimeout, it's discarded.
func NewPool(factory ConnOpen, capacity int, idleTimeout time.Duration) *Pool {
	p := &Pool{conns: make(chan *Conn, capacity), factory: factory, idleTimeout: idleTimeout}
	p.available = sync.NewCond(&p.mu)
	return p
}

// Get will return the next available connection. If none is available, and capacity
// has not been reached, it will create a new one using the factory. Otherwise,
// it will indefinitely wait till the next connection becomes available.
func (p *Pool) Get() (*Conn, error) {
	return p.get(true)
}

// TryGet will return the next available connection. If none is available, and capacity
// has not been reached, it will create a new one using the factory. Otherwise,
// it will return nil with no error.
func (p *Pool) TryGet() (*Conn, error) {
	return p.get(false)
}

func (p *Pool) get(wait bool) (*Conn, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	// Any waits in this loop will release the lock, and it will be
	// reacquired before the waits return.
	for {
		select {
		case conn := <-p.conns:
			// Found a free resource in the channel
			if p.idleTimeout > 0 && conn.timeUsed.Add(p.idleTimeout).Sub(time.Now()) < 0 {
				// connection has been idle for too long. Discard & go for next.
				go conn.Close()
				p.size--
				// Nobody else should be waiting, but signal anyway.
				p.available.Signal()
				continue
			}
			return conn, nil
		default:
			// connection channel is empty
			if p.size >= cap(p.conns) {
				// The pool is full
				if wait {
					p.available.Wait()
					continue
				}
				return nil, nil
			}
			// Pool is not full. Create a connection.
			var conn *Conn
			var err error
			if conn, err = p.waitForCreate(); err != nil {
				// size was decremented, and somebody could be waiting.
				p.available.Signal()
				return nil, err
			}
			// Creation successful. Account for this by incrementing size.
			p.size++
			return conn, err
		}
	}
}

func (p *Pool) waitForCreate() (*Conn, error) {
	// Prevent thundering herd: increment size before creating resource, and decrement after.
	p.size++
	p.mu.Unlock()
	defer func() {
		p.mu.Lock()
		p.size--
	}()
	return p.factory()
}

// Release will return a connection to the pool. You MUST return every connection to the pool,
// even if it's closed. If a connection is closed, Release will discard it.
func (p *Pool) Release(c *Conn) {
	p.mu.Lock()
	defer p.available.Signal()
	defer p.mu.Unlock()

	if p.size > cap(p.conns) {
		go c.Close()
		p.size--
	} else if c.IsClosed() {
		p.size--
	} else {
		if len(p.conns) == cap(p.conns) {
			panic("unexpected")
		}
		c.timeUsed = time.Now()
		p.conns <- c
	}
}

// Close empties the pool closing all its connections.
// It waits for all connections to be returned (Release).
func (p *Pool) Close() {
	p.mu.Lock()
	defer p.mu.Unlock()
	for p.size > 0 {
		select {
		case conn := <-p.conns:
			go conn.Close()
			p.size--
		default:
			p.available.Wait()
		}
	}
	p.factory = nil
}

// IsClosed returns true when the pool has been closed.
func (p *Pool) IsClosed() bool {
	return p.factory == nil
}

// SetCapacity changes the capacity of the pool.
// You can use it to expand or shrink.
func (p *Pool) SetCapacity(capacity int) {
	p.mu.Lock()
	defer p.available.Broadcast()
	defer p.mu.Unlock()

	nr := make(chan *Conn, capacity)
	// This loop transfers connections from the old channel
	// to the new one, until it fills up or runs out.
	// It discards extras, if any.
	for {
		select {
		case conn := <-p.conns:
			if len(nr) < cap(nr) {
				nr <- conn
			} else {
				go conn.Close()
				p.size--
			}
			continue
		default:
		}
		break
	}
	p.conns = nr
}

func (p *Pool) SetIdleTimeout(idleTimeout time.Duration) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.idleTimeout = idleTimeout
}
