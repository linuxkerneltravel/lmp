// Copyright 2010 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package sqlite

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"

	"github.com/gwenn/yacr"
)

type csvModule struct {
}

// args[0] => module name
// args[1] => db name
// args[2] => table name
// args[3] => filename (maybe quoted: '...')
// args[i>3] :
//  - contains HEADER ignoring case => use first line in file as column names or skip first line if NAMES are specified
//  - contains NO_QUOTE ignoring case => no double quoted field expected in file
//  - single char (;) or quoted char (';') => values separator in file
//  - contains NAMES ignoring case => use args[i+1], ... as column names (until _TYPES_)
//  - contains TYPES ignoring case => use args[I+1], ... as column types
// Beware, empty args are skipped (..., ,...), use '' empty SQL string instead (..., '', ...).
// Adapted from:
//  - https://github.com/gwenn/sqlite-csv-ext
//  - http://www.ch-werner.de/sqliteodbc/html/csvtable_8c.html
func (m csvModule) Create(c *Conn, args []string) (VTab, error) {
	if len(args) < 4 {
		return nil, errors.New("no CSV file specified")
	}
	/* pull out name of csv file (remove quotes) */
	filename := args[3]
	if filename[0] == '\'' {
		filename = filename[1 : len(filename)-1]
	}
	/* if a custom delimiter specified, pull it out */
	var separator byte = ','
	/* should the header zRow be used */
	header := false
	quoted := true
	guess := true
	var cols, types []string
	for i := 4; i < len(args); i++ {
		arg := args[i]
		switch {
		case types != nil:
			if arg[0] == '\'' {
				arg = arg[1 : len(arg)-1]
			}
			types = append(types, arg)
		case cols != nil:
			if strings.ToUpper(arg) == "_TYPES_" {
				types = make([]string, 0, len(cols))
			} else {
				cols = append(cols, arg)
			}
		case len(arg) == 1:
			separator = arg[0]
			guess = false
		case len(arg) == 3 && arg[0] == '\'':
			separator = arg[1]
			guess = false
		case strings.Contains(strings.ToUpper(arg), "HEADER"):
			header = true
		case strings.Contains(strings.ToUpper(arg), "NO_QUOTE"):
			quoted = false
		case strings.Contains(strings.ToUpper(arg), "NAMES"):
			cols = make([]string, 0, 10)
		case strings.Contains(strings.ToUpper(arg), "TYPES"):
			types = make([]string, 0, 10)
		}
	}
	/* open the source csv file */
	file, err := os.Open(filename)
	if err != nil {
		return nil, fmt.Errorf("error opening CSV file: '%s'", filename)
	}
	defer file.Close()
	/* Read first zRow to obtain column names/number */
	vTab := &csvTab{f: filename, sep: separator, quoted: quoted, cols: make([]string, 0, 10)}
	vTab.maxLength = int(c.Limit(LimitLength))
	vTab.maxColumn = int(c.Limit(LimitColumn))

	reader := yacr.NewReader(file, separator, quoted, guess)
	if header {
		reader.Split(vTab.split(reader.ScanField))
	}
	if err = vTab.readRow(reader); err != nil {
		return nil, err
	}
	named := header
	if len(cols) > 0 { // headers ignored
		// TODO check len(cols) == len(vTab.cols) ?
		vTab.cols = cols
		named = true
	}
	if len(vTab.cols) == 0 {
		if len(types) == 0 {
			return nil, errors.New("no column name/type specified")
		}
		vTab.cols = types
	}

	if guess {
		vTab.sep = reader.Sep()
	}
	/* Create the underlying relational database schema. If
	 * that is successful, call sqlite3_declare_vtab() to configure
	 * the csv table schema.
	 */
	sql := "CREATE TABLE x("
	tail := ", "
	for i, col := range vTab.cols {
		if i == len(vTab.cols)-1 {
			tail = ");"
		}
		colType := ""
		if len(types) > i {
			colType = " " + types[i]
		}
		if named {
			if len(col) == 0 {
				return nil, errors.New("no column name found")
			}
			sql = fmt.Sprintf("%s\"%s\"%s%s", sql, col, colType, tail)
		} else {
			sql = fmt.Sprintf("%scol%d%s%s", sql, i+1, colType, tail)
		}
	}
	if err = c.DeclareVTab(sql); err != nil {
		return nil, err
	}

	vTab.affinities = make([]Affinity, len(vTab.cols))
	if len(types) > 0 {
		for i, typ := range types {
			if i >= len(vTab.affinities) {
				break
			}
			vTab.affinities[i] = typeAffinity(typ)
		}
	}
	return vTab, nil
}
func (m csvModule) Connect(c *Conn, args []string) (VTab, error) {
	return m.Create(c, args)
}

func (m csvModule) DestroyModule() { // nothing to do
}

type csvTab struct {
	f              string
	sep            byte
	quoted         bool
	eof            bool
	offsetFirstRow int64
	cols           []string
	affinities     []Affinity

	maxLength int
	maxColumn int
}

func (v *csvTab) split(original bufio.SplitFunc) bufio.SplitFunc {
	return func(data []byte, atEOF bool) (advance int, token []byte, err error) {
		advance, token, err = original(data, atEOF)
		v.offsetFirstRow += int64(advance)
		return
	}
}

func (v *csvTab) readRow(r *yacr.Reader) error {
	v.cols = v.cols[:0]
	for {
		if !r.Scan() {
			err := r.Err()
			v.eof = err == nil
			return err
		}
		if r.EndOfRecord() && len(r.Bytes()) == 0 { // skip empty line (or line comment)
			continue
		}
		col := r.Text()
		if len(col) >= v.maxLength {
			return fmt.Errorf("CSV row is too long (>= %d)", v.maxLength)
		}
		v.cols = append(v.cols, col)
		if len(v.cols) >= v.maxColumn {
			return fmt.Errorf("too many columns (>= %d)", v.maxColumn)
		}
		if r.EndOfRecord() {
			break
		}
	}
	return nil
}

func (v *csvTab) BestIndex() error {
	return nil
}
func (v *csvTab) Disconnect() error {
	return nil
}
func (v *csvTab) Destroy() error {
	return nil
}
func (v *csvTab) Open() (VTabCursor, error) {
	f, err := os.Open(v.f)
	if err != nil {
		return nil, err
	}
	return &csvTabCursor{vTab: v, f: f, rowNumber: 0}, nil
}

type csvTabCursor struct {
	vTab      *csvTab
	f         *os.File
	r         *yacr.Reader
	rowNumber int64
}

func (vc *csvTabCursor) Close() error {
	return vc.f.Close()
}
func (vc *csvTabCursor) Filter() error {
	v := vc.vTab
	/* seek back to start of first zRow */
	v.eof = false
	if _, err := vc.f.Seek(v.offsetFirstRow, io.SeekStart); err != nil {
		return err
	}
	vc.rowNumber = 0
	/* a new reader/scanner must be created because there is no way to reset its internal buffer/state (which has been invalidated by the SEEK_SET)*/
	vc.r = yacr.NewReader(vc.f, v.sep, v.quoted, false)
	/* read and parse next line */
	return vc.Next()
}
func (vc *csvTabCursor) Next() error {
	v := vc.vTab
	if v.eof {
		return io.EOF
	}
	if vc.r == nil {
		vc.r = yacr.NewReader(vc.f, v.sep, v.quoted, false)
	}
	/* read the next row of data */
	err := v.readRow(vc.r)
	if err == nil {
		vc.rowNumber++
	}
	return err
}
func (vc *csvTabCursor) EOF() bool {
	return vc.vTab.eof
}
func (vc *csvTabCursor) Column(c *Context, col int) error {
	cols := vc.vTab.cols
	if col < 0 || col >= len(cols) {
		return fmt.Errorf("column index out of bounds: %d", col)
	}
	if cols == nil {
		c.ResultNull()
		return nil
	}
	affinity := vc.vTab.affinities[col]
	if affinity == Integral || affinity == Numerical {
		if i, err := strconv.ParseInt(cols[col], 10, 64); err == nil {
			c.ResultInt64(i)
			return nil
		}
	}
	if affinity == Real || affinity == Numerical {
		if f, err := strconv.ParseFloat(cols[col], 64); err == nil {
			c.ResultDouble(f)
			return nil
		}
	}
	c.ResultText(cols[col])
	return nil
}
func (vc *csvTabCursor) Rowid() (int64, error) {
	return vc.rowNumber, nil
}

// LoadCsvModule loads CSV virtual table module.
//   CREATE VIRTUAL TABLE vtab USING csv('test.csv', USE_HEADER_ROW, NO_QUOTE)
func LoadCsvModule(db *Conn) error {
	return db.CreateModule("csv", csvModule{})
}

// ExportTableToCSV exports table or view content to CSV.
// 'headers' flag turns output of headers on or off.
// NULL values are output as specified by 'nullvalue' parameter.
func (c *Conn) ExportTableToCSV(dbName, table string, nullvalue string, headers bool, w *yacr.Writer) error {
	var sql string
	if len(dbName) == 0 {
		sql = fmt.Sprintf(`SELECT * FROM "%s"`, escapeQuote(table))
	} else {
		sql = fmt.Sprintf(`SELECT * FROM %s."%s"`, doubleQuote(dbName), escapeQuote(table))
	}
	s, err := c.prepare(sql)
	if err != nil {
		return err
	}
	defer s.finalize()
	return s.ExportToCSV(nullvalue, headers, w)
}

// ExportToCSV exports statement result to CSV.
// 'headers' flag turns output of headers on or off.
// NULL values are output as specified by 'nullvalue' parameter.
func (s *Stmt) ExportToCSV(nullvalue string, headers bool, w *yacr.Writer) error {
	if headers {
		for _, header := range s.ColumnNames() {
			w.Write([]byte(header))
		}
		w.EndOfRecord()
		if err := w.Err(); err != nil {
			return err
		}
	}
	s.Select(func(s *Stmt) error {
		for i := 0; i < s.ColumnCount(); i++ {
			rb, null := s.ScanRawBytes(i)
			if null {
				w.Write([]byte(nullvalue))
			} else {
				w.Write(rb)
			}
		}
		w.EndOfRecord()
		return w.Err()
	})
	w.Flush()
	return w.Err()
}

// ImportConfig gathers import parameters.
type ImportConfig struct {
	Name      string     // the name of the input; used only for error reports
	Separator byte       // CSV separator
	Quoted    bool       // CSV fields are quoted or not
	Guess     bool       // guess separator
	Trim      bool       // optional, trim spaces
	Comment   byte       // optinal, comment marker
	Headers   bool       // skip headers (first line)
	Types     []Affinity // optional, when target table does not exist, specify columns type
	Log       io.Writer  // optional, used to trace lines in error
}

func (ic ImportConfig) getType(i int) string {
	if i >= len(ic.Types) || ic.Types[i] == Textual {
		return "TEXT"
	}
	if ic.Types[i] == Integral {
		return "INT"
	}
	if ic.Types[i] == Real {
		return "REAL"
	}
	if ic.Types[i] == Numerical {
		return "NUMERIC"
	}
	return ""
}

// ImportCSV imports CSV data into the specified table (which may not exist yet).
// Code is adapted from .import command implementation in SQLite3 shell sources.
func (c *Conn) ImportCSV(in io.Reader, ic ImportConfig, dbName, table string) error {
	columns, err := c.Columns(dbName, table)
	if err != nil {
		return err
	}
	r := yacr.NewReader(in, ic.Separator, ic.Quoted, ic.Guess)
	r.Trim = ic.Trim
	r.Comment = ic.Comment
	nCol := len(columns)
	if nCol == 0 { // table does not exist, let's create it
		var sql string
		if len(dbName) == 0 {
			sql = fmt.Sprintf(`CREATE TABLE "%s" `, escapeQuote(table))
		} else {
			sql = fmt.Sprintf(`CREATE TABLE %s."%s" `, doubleQuote(dbName), escapeQuote(table))
		}
		sep := '('
		// TODO if headers flag is false...
		for i := 0; r.Scan(); i++ {
			if i == 0 && r.EndOfRecord() && len(r.Bytes()) == 0 { // empty line
				i = -1
				continue
			}
			sql += fmt.Sprintf("%c\n  \"%s\" %s", sep, r.Text(), ic.getType(i))
			sep = ','
			nCol++
			if r.EndOfRecord() {
				break
			}
		}
		if err = r.Err(); err != nil {
			return err
		}
		if sep == '(' {
			return errors.New("empty file/input")
		}
		sql += "\n)"
		if err = c.FastExec(sql); err != nil {
			return err
		}
	} else if ic.Headers { // skip headers line
		for r.Scan() {
			if r.EndOfRecord() {
				break
			}
		}
		if err = r.Err(); err != nil {
			return err
		}
	}

	var sql string
	if len(dbName) == 0 {
		sql = fmt.Sprintf(`INSERT INTO "%s" VALUES (?%s)`, escapeQuote(table), strings.Repeat(", ?", nCol-1))
	} else {
		sql = fmt.Sprintf(`INSERT INTO %s."%s" VALUES (?%s)`, doubleQuote(dbName), escapeQuote(table), strings.Repeat(", ?", nCol-1))
	}
	s, err := c.prepare(sql)
	if err != nil {
		return err
	}
	defer s.Finalize()
	ac := c.GetAutocommit()
	if ac {
		if err = c.Begin(); err != nil {
			return err
		}
	}
	defer func() {
		if err != nil && ac {
			_ = c.Rollback()
		}
	}()
	startLine := r.LineNumber()
	for i := 1; r.Scan(); i++ {
		if i == 1 && r.EndOfRecord() && len(r.Bytes()) == 0 { // empty line
			i = 0
			startLine = r.LineNumber()
			continue
		}
		if i <= nCol {
			if err = s.BindByIndex(i, r.Text()); err != nil {
				return err
			}
		}
		if r.EndOfRecord() {
			if i < nCol {
				if ic.Log != nil {
					_, _ = fmt.Fprintf(ic.Log, "%s:%d: expected %d columns but found %d - filling the rest with NULL\n", ic.Name, startLine, nCol, i)
				}
				for ; i <= nCol; i++ {
					if err = s.BindByIndex(i, nil); err != nil {
						return err
					}
				}
			} else if i > nCol && ic.Log != nil {
				_, _ = fmt.Fprintf(ic.Log, "%s:%d: expected %d columns but found %d - extras ignored\n", ic.Name, startLine, nCol, i)
			}
			if _, err = s.Next(); err != nil {
				return err
			}
			i = 0
			startLine = r.LineNumber()
		}
	}
	if err = r.Err(); err != nil {
		return err
	}
	if ac {
		if err = c.Commit(); err != nil {
			return err
		}
	}
	return nil
}
