// Copyright 2010 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package sqlite

/*
#include <sqlite3.h>
#include <stdlib.h>
*/
import "C"

import (
	"errors"
	"time"
	"unsafe"
)

// NewBackup initializes the backup/copy of the content of one database (source) to another (destination).
// The database name is "main", "temp", or the name specified in an ATTACH statement.
//
// (See http://sqlite.org/c3ref/backup_finish.html#sqlite3backupinit)
func NewBackup(dst *Conn, dstName string, src *Conn, srcName string) (*Backup, error) {
	if dst == nil || src == nil {
		return nil, errors.New("nil sqlite backup source or destination")
	}
	dname := C.CString(dstName)
	sname := C.CString(srcName)

	sb := C.sqlite3_backup_init(dst.db, dname, src.db, sname)
	C.free(unsafe.Pointer(sname))
	C.free(unsafe.Pointer(dname))
	if sb == nil {
		return nil, dst.error(C.sqlite3_errcode(dst.db), "backup init failed")
	}
	return &Backup{sb, dst, src}, nil
}

// The Backup object records state information about an ongoing online backup operation.
// (See http://sqlite.org/c3ref/backup.html)
type Backup struct {
	sb       *C.sqlite3_backup
	dst, src *Conn
}

// Step copies up to N pages between the source and destination databases.
// (See http://sqlite.org/c3ref/backup_finish.html#sqlite3backupstep)
func (b *Backup) Step(npage int32) error {
	if b == nil {
		return errors.New("nil sqlite backup")
	}
	rv := C.sqlite3_backup_step(b.sb, C.int(npage))
	if rv == C.SQLITE_OK || Errno(rv&0xFF) == ErrBusy || Errno(rv&0xFF) == ErrLocked { // TODO Trace busy/locked errors
		return nil
	} else if rv == C.SQLITE_DONE {
		return Errno(rv)
	}
	return b.dst.error(rv, "backup step failed")
}

// BackupStatus reports backup progression
type BackupStatus struct {
	Remaining int
	PageCount int
}

// Status returns the number of pages still to be backed up and the total number of pages in the source database file.
// (See http://sqlite.org/c3ref/backup_finish.html#sqlite3backupremaining)
func (b *Backup) Status() BackupStatus {
	return BackupStatus{int(C.sqlite3_backup_remaining(b.sb)), int(C.sqlite3_backup_pagecount(b.sb))}
}

// Run starts the backup:
// - copying up to 'npage' pages between the source and destination at each step,
// - sleeping 'sleepNs' between steps,
// - notifying the caller of backup progress throw the channel 'c',
// - closing the backup when done or when an error happens.
// Sleeping is disabled if 'sleepNs' is zero or negative.
// Notification is disabled if 'c' is null.
// (See http://sqlite.org/c3ref/backup_finish.html#sqlite3backupstep, sqlite3_backup_remaining and sqlite3_backup_pagecount)
func (b *Backup) Run(npage int32, sleepNs time.Duration, c chan<- BackupStatus) error {
	var err error
	for {
		err = b.Step(npage)
		if err != nil {
			break
		}
		if c != nil {
			c <- b.Status()
		}
		if sleepNs > 0 {
			time.Sleep(sleepNs)
		}
	}
	if err != Done {
		_ = b.Close()
	} else {
		if c != nil {
			c <- b.Status()
		}
		err = b.Close()
	}
	if err != nil && err != Done {
		return err
	}
	return nil
}

// Close finishes/stops the backup.
// (See http://sqlite.org/c3ref/backup_finish.html#sqlite3backupfinish)
func (b *Backup) Close() error {
	if b == nil {
		return errors.New("nil sqlite backup")
	}
	if b.sb == nil {
		return nil
	}
	rv := C.sqlite3_backup_finish(b.sb) // must be called only once
	b.sb = nil
	if rv != C.SQLITE_OK {
		return b.dst.error(rv, "backup finish failed")
	}
	return nil
}
