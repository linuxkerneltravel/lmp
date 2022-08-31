// Copyright 2010 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package sqlite

/*
#include <sqlite3.h>
#include <stdlib.h>

extern void goXAuxDataDestroy(void*);
extern void goXDestroy(void*);
extern void goXFunc(sqlite3_context *ctx, int argc, sqlite3_value **argv);
extern void goXStep(sqlite3_context *ctx, int argc, sqlite3_value **argv);
extern void goXFinal(sqlite3_context *ctx);

// These wrappers are necessary because SQLITE_TRANSIENT
// is a pointer constant, and cgo doesn't translate them correctly.
static inline void my_result_text(sqlite3_context *ctx, char *p, int np) {
       sqlite3_result_text(ctx, p, np, SQLITE_TRANSIENT);
}
static inline void my_result_blob(sqlite3_context *ctx, void *p, int np) {
       sqlite3_result_blob(ctx, p, np, SQLITE_TRANSIENT);
}
*/
import "C"

import (
	"fmt"
	"math"
	"reflect"
	"unsafe"
)

/*
Database Connection For Functions
http://sqlite.org/c3ref/context_db_handle.html

sqlite3 *sqlite3_context_db_handle(sqlite3_context*);
*/

// Context common to function and virtual table
// (See http://sqlite.org/c3ref/context.html)
type Context C.sqlite3_context

// FunctionContext common to scalar and aggregate functions
// (See http://sqlite.org/c3ref/context.html)
type FunctionContext struct {
	sc   *Context
	argv []*C.sqlite3_value
}

// ScalarContext is used to represent context associated to scalar function
type ScalarContext struct {
	FunctionContext
	ad  map[int]interface{} // Function Auxiliary Data
	udf *sqliteFunction
}

// AggregateContext is used to represent context associated to aggregate function
type AggregateContext struct {
	FunctionContext
	Aggregate interface{}
}

// Result sets the result of an SQL function.
func (c *FunctionContext) Result(r interface{}) {
	switch r := r.(type) {
	case nil:
		c.ResultNull()
	case string:
		c.ResultText(r)
	case int:
		c.ResultInt(r)
	case int64:
		c.ResultInt64(r)
	case byte:
		c.ResultInt(int(r))
	case bool:
		c.ResultBool(r)
	case float32:
		c.ResultDouble(float64(r))
	case float64:
		c.ResultDouble(r)
	case []byte:
		c.ResultBlob(r)
	case ZeroBlobLength:
		c.ResultZeroblob(r)
	case error:
		c.ResultError(r.Error())
	default:
		panic(fmt.Sprintf("unsupported type in Result: %q", reflect.TypeOf(r)))
	}
}

// ResultBool sets the result of an SQL function.
func (c *Context) ResultBool(b bool) {
	if b {
		c.ResultInt(1)
	} else {
		c.ResultInt(0)
	}
}

// ResultBool sets the result of an SQL function.
func (c *FunctionContext) ResultBool(b bool) {
	c.sc.ResultBool(b)
}

// ResultBlob sets the result of an SQL function.
// (See sqlite3_result_blob, http://sqlite.org/c3ref/result_blob.html)
func (c *Context) ResultBlob(b []byte) {
	if i64 && len(b) > math.MaxInt32 {
		C.sqlite3_result_error_toobig((*C.sqlite3_context)(c))
		return
	}
	var p *byte
	if len(b) > 0 {
		p = &b[0]
	}
	C.my_result_blob((*C.sqlite3_context)(c), unsafe.Pointer(p), C.int(len(b)))
}

// ResultBlob sets the result of an SQL function.
func (c *FunctionContext) ResultBlob(b []byte) {
	c.sc.ResultBlob(b)
}

// ResultDouble sets the result of an SQL function.
// (See sqlite3_result_double, http://sqlite.org/c3ref/result_blob.html)
func (c *Context) ResultDouble(d float64) {
	C.sqlite3_result_double((*C.sqlite3_context)(c), C.double(d))
}

// ResultDouble sets the result of an SQL function.
func (c *FunctionContext) ResultDouble(d float64) {
	c.sc.ResultDouble(d)
}

// ResultError sets the result of an SQL function.
// (See sqlite3_result_error, http://sqlite.org/c3ref/result_blob.html)
func (c *FunctionContext) ResultError(msg string) {
	cs, l := cstring(msg)
	C.sqlite3_result_error((*C.sqlite3_context)(c.sc), cs, l)
}

// ResultErrorTooBig sets the result of an SQL function.
// (See sqlite3_result_error_toobig, http://sqlite.org/c3ref/result_blob.html)
func (c *FunctionContext) ResultErrorTooBig() {
	C.sqlite3_result_error_toobig((*C.sqlite3_context)(c.sc))
}

// ResultErrorNoMem sets the result of an SQL function.
// (See sqlite3_result_error_nomem, http://sqlite.org/c3ref/result_blob.html)
func (c *FunctionContext) ResultErrorNoMem() {
	C.sqlite3_result_error_nomem((*C.sqlite3_context)(c.sc))
}

// ResultErrorCode sets the result of an SQL function.
// (See sqlite3_result_error_code, http://sqlite.org/c3ref/result_blob.html)
func (c *FunctionContext) ResultErrorCode(e Errno) {
	C.sqlite3_result_error_code((*C.sqlite3_context)(c.sc), C.int(e))
}

// ResultInt sets the result of an SQL function.
// (See sqlite3_result_int, http://sqlite.org/c3ref/result_blob.html)
func (c *Context) ResultInt(i int) {
	if i64 && (i > math.MaxInt32 || i < math.MinInt32) {
		C.sqlite3_result_int64((*C.sqlite3_context)(c), C.sqlite3_int64(i))
	} else {
		C.sqlite3_result_int((*C.sqlite3_context)(c), C.int(i))
	}
}

// ResultInt sets the result of an SQL function.
func (c *FunctionContext) ResultInt(i int) {
	c.sc.ResultInt(i)
}

// ResultInt64 sets the result of an SQL function.
// (See sqlite3_result_int64, http://sqlite.org/c3ref/result_blob.html)
func (c *Context) ResultInt64(i int64) {
	C.sqlite3_result_int64((*C.sqlite3_context)(c), C.sqlite3_int64(i))
}

// ResultInt64 sets the result of an SQL function.
func (c *FunctionContext) ResultInt64(i int64) {
	c.sc.ResultInt64(i)
}

// ResultNull sets the result of an SQL function.
// (See sqlite3_result_null, http://sqlite.org/c3ref/result_blob.html)
func (c *Context) ResultNull() {
	C.sqlite3_result_null((*C.sqlite3_context)(c))
}

// ResultNull sets the result of an SQL function.
func (c *FunctionContext) ResultNull() {
	c.sc.ResultNull()
}

// ResultText sets the result of an SQL function.
// (See sqlite3_result_text, http://sqlite.org/c3ref/result_blob.html)
func (c *Context) ResultText(s string) {
	cs, l := cstring(s)
	C.my_result_text((*C.sqlite3_context)(c), cs, l)
}

// ResultText sets the result of an SQL function.
func (c *FunctionContext) ResultText(s string) {
	c.sc.ResultText(s)
}

// ResultValue sets the result of an SQL function.
// The leftmost value is number 0.
// (See sqlite3_result_value, http://sqlite.org/c3ref/result_blob.html)
func (c *FunctionContext) ResultValue(i int) {
	C.sqlite3_result_value((*C.sqlite3_context)(c.sc), c.argv[i])
}

// ResultZeroblob sets the result of an SQL function.
// (See sqlite3_result_zeroblob, http://sqlite.org/c3ref/result_blob.html)
func (c *Context) ResultZeroblob(n ZeroBlobLength) {
	C.sqlite3_result_zeroblob((*C.sqlite3_context)(c), C.int(n))
}

// ResultZeroblob sets the result of an SQL function.
func (c *FunctionContext) ResultZeroblob(n ZeroBlobLength) {
	c.sc.ResultZeroblob(n)
}

// UserData returns the user data for functions.
// (See http://sqlite.org/c3ref/user_data.html)
func (c *FunctionContext) UserData() interface{} {
	udf := (*sqliteFunction)(C.sqlite3_user_data((*C.sqlite3_context)(c.sc)))
	return udf.pApp
}

// GetAuxData returns function auxiliary data.
// (See sqlite3_get_auxdata, http://sqlite.org/c3ref/get_auxdata.html)
func (c *ScalarContext) GetAuxData(n int) interface{} {
	if len(c.ad) == 0 {
		return nil
	}
	return c.ad[n]
}

// SetAuxData sets function auxiliary data.
// No destructor is needed a priori
// (See sqlite3_set_auxdata, http://sqlite.org/c3ref/get_auxdata.html)
func (c *ScalarContext) SetAuxData(n int, ad interface{}) {
	if len(c.ad) == 0 {
		c.ad = make(map[int]interface{})
	}
	c.ad[n] = ad
}

// Bool obtains a SQL function parameter value.
// The leftmost value is number 0.
func (c *FunctionContext) Bool(i int) bool {
	return c.Int(i) != 0
}

// Blob obtains a SQL function parameter value.
// The leftmost value is number 0.
// (See sqlite3_value_blob and sqlite3_value_bytes, http://sqlite.org/c3ref/value_blob.html)
func (c *FunctionContext) Blob(i int) []byte {
	p := C.sqlite3_value_blob(c.argv[i])
	if p == nil {
		return nil
	}

	n := C.sqlite3_value_bytes(c.argv[i])
	// value = (*[1 << 30]byte)(unsafe.Pointer(p))[:n]
	return C.GoBytes(p, n) // The memory space used to hold strings and BLOBs is freed automatically.
}

// Double obtains a SQL function parameter value.
// The leftmost value is number 0.
// (See sqlite3_value_double, http://sqlite.org/c3ref/value_blob.html)
func (c *FunctionContext) Double(i int) float64 {
	return float64(C.sqlite3_value_double(c.argv[i]))
}

// Int obtains a SQL function parameter value.
// The leftmost value is number 0.
// (See sqlite3_value_int, http://sqlite.org/c3ref/value_blob.html)
func (c *FunctionContext) Int(i int) int {
	return int(C.sqlite3_value_int(c.argv[i]))
}

// Int64 obtains a SQL function parameter value.
// The leftmost value is number 0.
// (See sqlite3_value_int64, http://sqlite.org/c3ref/value_blob.html)
func (c *FunctionContext) Int64(i int) int64 {
	return int64(C.sqlite3_value_int64(c.argv[i]))
}

// Text obtains a SQL function parameter value.
// The leftmost value is number 0.
// (See sqlite3_value_text, http://sqlite.org/c3ref/value_blob.html)
func (c *FunctionContext) Text(i int) string {
	p := C.sqlite3_value_text(c.argv[i])
	if p == nil {
		return ""
	}
	n := C.sqlite3_value_bytes(c.argv[i])
	return C.GoStringN((*C.char)(unsafe.Pointer(p)), n)
}

// Type obtains a SQL function parameter value type.
// The leftmost value is number 0.
// (See sqlite3_value_type, http://sqlite.org/c3ref/value_blob.html)
func (c *FunctionContext) Type(i int) Type {
	return Type(C.sqlite3_value_type(c.argv[i]))
}

// NumericType obtains a SQL function parameter value numeric type (with possible conversion).
// The leftmost value is number 0.
// (See sqlite3_value_numeric_type, http://sqlite.org/c3ref/value_blob.html)
func (c *FunctionContext) NumericType(i int) Type {
	return Type(C.sqlite3_value_numeric_type(c.argv[i]))
}

// Value obtains a SQL function parameter value depending on its type.
func (c *FunctionContext) Value(i int) interface{} {
	var value interface{}
	switch c.Type(i) {
	case Null:
		value = nil
	case Text:
		value = c.Text(i)
	case Integer:
		value = c.Int64(i)
	case Float:
		value = c.Double(i)
	case Blob:
		value = c.Blob(i)
	default:
		panic("The value type is not one of SQLITE_INTEGER, SQLITE_FLOAT, SQLITE_TEXT, SQLITE_BLOB, or SQLITE_NULL")
	}
	return value
}

// ScalarFunction is the expected signature of scalar function implemented in Go
type ScalarFunction func(ctx *ScalarContext, nArg int)

// StepFunction is the expected signature of step function implemented in Go
type StepFunction func(ctx *AggregateContext, nArg int)

// FinalFunction is the expected signature of final function implemented in Go
type FinalFunction func(ctx *AggregateContext)

// DestroyDataFunction is the expected signature of function used to finalize user data.
type DestroyDataFunction func(pApp interface{})

type sqliteFunction struct {
	scalar     ScalarFunction
	step       StepFunction
	final      FinalFunction
	d          DestroyDataFunction
	pApp       interface{}
	scalarCtxs map[*ScalarContext]struct{}
	aggrCtxs   map[*AggregateContext]struct{}
}

//export goXAuxDataDestroy
func goXAuxDataDestroy(ad unsafe.Pointer) {
	c := (*ScalarContext)(ad)
	if c != nil {
		delete(c.udf.scalarCtxs, c)
	}
	//	fmt.Printf("Contexts: %v\n", c.udf.scalarCtxs)
}

//export goXFunc
func goXFunc(ctx *C.sqlite3_context, argc C.int, argv **C.sqlite3_value) {
	udf := (*sqliteFunction)(C.sqlite3_user_data(ctx))
	// To avoid the creation of a Context at each call, just put it in auxdata
	c := (*ScalarContext)(C.sqlite3_get_auxdata(ctx, 0))
	if c == nil {
		c = new(ScalarContext)
		c.sc = (*Context)(ctx)
		c.udf = udf
		C.sqlite3_set_auxdata(ctx, 0, unsafe.Pointer(c), (*[0]byte)(C.goXAuxDataDestroy))
		// To make sure it is not cged
		udf.scalarCtxs[c] = struct{}{}
	}
	n := int(argc)
	c.argv = (*[1 << 30]*C.sqlite3_value)(unsafe.Pointer(argv))[:n:n]
	udf.scalar(c, n)
	c.argv = nil
}

//export goXStep
func goXStep(ctx *C.sqlite3_context, argc C.int, argv **C.sqlite3_value) {
	udf := (*sqliteFunction)(C.sqlite3_user_data(ctx))
	var cp unsafe.Pointer
	cp = C.sqlite3_aggregate_context(ctx, C.int(unsafe.Sizeof(cp)))
	if cp != nil {
		var c *AggregateContext
		p := *(*unsafe.Pointer)(cp)
		if p == nil {
			c = new(AggregateContext)
			c.sc = (*Context)(ctx)
			*(*unsafe.Pointer)(cp) = unsafe.Pointer(c)
			// To make sure it is not cged
			udf.aggrCtxs[c] = struct{}{}
		} else {
			c = (*AggregateContext)(p)
		}

		n := int(argc)
		c.argv = (*[1 << 30]*C.sqlite3_value)(unsafe.Pointer(argv))[:n:n]
		udf.step(c, n)
		c.argv = nil
	}
}

//export goXFinal
func goXFinal(ctx *C.sqlite3_context) {
	udf := (*sqliteFunction)(C.sqlite3_user_data(ctx))
	cp := C.sqlite3_aggregate_context(ctx, 0)
	if cp != nil {
		p := *(*unsafe.Pointer)(cp)
		if p != nil {
			c := (*AggregateContext)(p)
			delete(udf.aggrCtxs, c)
			c.sc = (*Context)(ctx)
			udf.final(c)
		}
	}
	//	fmt.Printf("Contexts: %v\n", udf.aggrCtxts)
}

//export goXDestroy
func goXDestroy(pApp unsafe.Pointer) {
	udf := (*sqliteFunction)(pApp)
	if udf.d != nil {
		udf.d(udf.pApp)
	}
}

const sqliteDeterministic = 0x800 // C.SQLITE_DETERMINISTIC

// CreateScalarFunction creates or redefines SQL scalar functions.
// Cannot be used with Go >= 1.6 and cgocheck enabled.
// TODO Make possible to specify the preferred encoding
// (See http://sqlite.org/c3ref/create_function.html)
func (c *Conn) CreateScalarFunction(functionName string, nArg int32, deterministic bool, pApp interface{},
	f ScalarFunction, d DestroyDataFunction) error {
	var eTextRep C.int = C.SQLITE_UTF8
	if deterministic {
		eTextRep = eTextRep | sqliteDeterministic
	}
	fname := C.CString(functionName)
	defer C.free(unsafe.Pointer(fname))
	if f == nil {
		if len(c.udfs) > 0 {
			delete(c.udfs, functionName)
		}
		return c.error(C.sqlite3_create_function_v2(c.db, fname, C.int(nArg), eTextRep, nil, nil, nil, nil, nil),
			fmt.Sprintf("<Conn.CreateScalarFunction(%q)", functionName))
	}
	// To make sure it is not gced, keep a reference in the connection.
	udf := &sqliteFunction{f, nil, nil, d, pApp, make(map[*ScalarContext]struct{}), nil}
	if len(c.udfs) == 0 {
		c.udfs = make(map[string]*sqliteFunction)
	}
	c.udfs[functionName] = udf // FIXME same function name with different args is not supported
	return c.error(C.sqlite3_create_function_v2(c.db, fname, C.int(nArg), eTextRep, unsafe.Pointer(udf), (*[0]byte)(C.goXFunc), nil, nil, (*[0]byte)(C.goXDestroy)),
		fmt.Sprintf("Conn.CreateScalarFunction(%q)", functionName))
}

// CreateAggregateFunction creates or redefines SQL aggregate functions.
// Cannot be used with Go >= 1.6 and cgocheck enabled.
// TODO Make possible to specify the preferred encoding
// (See http://sqlite.org/c3ref/create_function.html)
func (c *Conn) CreateAggregateFunction(functionName string, nArg int32, pApp interface{},
	step StepFunction, final FinalFunction, d DestroyDataFunction) error {
	fname := C.CString(functionName)
	defer C.free(unsafe.Pointer(fname))
	if step == nil {
		if len(c.udfs) > 0 {
			delete(c.udfs, functionName)
		}
		return c.error(C.sqlite3_create_function_v2(c.db, fname, C.int(nArg), C.SQLITE_UTF8, nil, nil, nil, nil, nil),
			fmt.Sprintf("<Conn.CreateAggregateFunction(%q)", functionName))
	}
	// To make sure it is not gced, keep a reference in the connection.
	udf := &sqliteFunction{nil, step, final, d, pApp, nil, make(map[*AggregateContext]struct{})}
	if len(c.udfs) == 0 {
		c.udfs = make(map[string]*sqliteFunction)
	}
	c.udfs[functionName] = udf // FIXME same function name with different args is not supported
	return c.error(C.sqlite3_create_function_v2(c.db, fname, C.int(nArg), C.SQLITE_UTF8, unsafe.Pointer(udf), nil, (*[0]byte)(C.goXStep), (*[0]byte)(C.goXFinal), (*[0]byte)(C.goXDestroy)),
		fmt.Sprintf("Conn.CreateAggregateFunction(%q)", functionName))
}
