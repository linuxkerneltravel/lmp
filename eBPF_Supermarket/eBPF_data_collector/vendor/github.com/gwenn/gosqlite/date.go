// Copyright 2010 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package sqlite

import (
	"bytes"
	"database/sql/driver"
	"fmt"
	"time"
)

const (
	julianDay    = 2440587.5 // 1970-01-01 00:00:00 is JD 2440587.5
	dayInSeconds = 60 * 60 * 24
)

// JulianDayToUTC transforms a julian day number into an UTC Time.
func JulianDayToUTC(jd float64) time.Time {
	jd -= julianDay
	jd *= dayInSeconds
	return time.Unix(int64(jd), 0).UTC()
}

// JulianDayToLocalTime transforms a julian day number into a local Time.
func JulianDayToLocalTime(jd float64) time.Time {
	jd -= julianDay
	jd *= dayInSeconds
	return time.Unix(int64(jd), 0)
}

// JulianDay converts a Time into a julian day number.
func JulianDay(t time.Time) float64 {
	ns := float64(t.Unix())
	if ns >= 0 {
		ns += 0.5
	}
	return ns/dayInSeconds + julianDay
}

// UnixTime is an alias used to persist time as int64 (max precision is 1s and timezone is lost)
type UnixTime struct {
	time.Time
}

// Scan implements the database/sql/Scanner interface.
func (t *UnixTime) Scan(src interface{}) error {
	if src == nil {
		t.Time = time.Time{}
		return nil
	} else if unixepoch, ok := src.(int64); ok {
		t.Time = time.Unix(unixepoch, 0) // local time
		return nil
	}
	return fmt.Errorf("unsupported UnixTime src: %T, %v", src, src)
}

// Value implements the database/sql/driver/Valuer interface
func (t UnixTime) Value() (driver.Value, error) {
	if t.IsZero() {
		return nil, nil
	}
	return t.Unix(), nil
}

// JulianTime is an alias used to persist time as float64 (max precision is 1s and timezone is lost)
type JulianTime struct {
	time.Time
}

// Scan implements the database/sql/Scanner interface.
func (t *JulianTime) Scan(src interface{}) error {
	if src == nil {
		t.Time = time.Time{}
		return nil
	} else if jd, ok := src.(int64); ok {
		t.Time = JulianDayToLocalTime(float64(jd)) // local time
		return nil
	} else if jd, ok := src.(float64); ok {
		t.Time = JulianDayToLocalTime(jd) // local time
		return nil
	}
	return fmt.Errorf("unsupported JulianTime src: %T", src)
}

// Value implements the database/sql/driver/Valuer interface
func (t JulianTime) Value() (driver.Value, error) {
	if t.IsZero() {
		return nil, nil
	}
	return JulianDay(t.Time), nil
}

// TimeStamp is an alias used to persist time as '2006-01-02T15:04:05.000Z07:00' string
type TimeStamp struct {
	time.Time
}

// Scan implements the database/sql/Scanner interface.
func (t *TimeStamp) Scan(src interface{}) error {
	if src == nil {
		t.Time = time.Time{}
		return nil
	} else if txt, ok := src.(string); ok {
		v, err := time.Parse("2006-01-02T15:04:05.000Z07:00", txt)
		if err != nil {
			return err
		}
		t.Time = v
		return nil
	}
	return fmt.Errorf("unsupported TimeStamp src: %T", src)
}

// Value implements the database/sql/driver/Valuer interface
func (t TimeStamp) Value() (driver.Value, error) {
	if t.IsZero() {
		return nil, nil
	}
	return t.Format("2006-01-02T15:04:05.000Z07:00"), nil
}

// MarshalText encoding.TextMarshaler interface.
// TimeStamp is formatted as null when zero or RFC3339.
func (t TimeStamp) MarshalText() ([]byte, error) {
	if t.IsZero() {
		return []byte("null"), nil
	}
	return t.Time.MarshalText()
}

// UnmarshalText implements the encoding.TextUnmarshaler interface.
// Date is expected in RFC3339 format or null.
func (t *TimeStamp) UnmarshalText(data []byte) error {
	if bytes.Equal(data, []byte("null")) {
		t.Time = time.Time{}
		return nil
	}
	ti := &t.Time
	return ti.UnmarshalText(data)
}
