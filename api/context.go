package api

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"io/ioutil"
	"math/rand"
	"net/http"
	"net/http/httputil"
	"path"
	"reflect"
	"runtime"

	"github.com/cihub/seelog"
	"github.com/gin-gonic/gin"
)

var logger seelog.LoggerInterface

func init() {
	var err error

	logger, err = seelog.LoggerFromConfigAsBytes([]byte(handlerLogConfig))
	if err != nil {
		panic(err)
	}
	logger.SetAdditionalStackDepth(1)
}

const _RequestIDKey = "__RequestID__"

// Context wrap gin Context
type Context struct {
	*gin.Context
	requestID string
}

// Tracef formats message according to format specifier
// and writes to log with level = Trace.
func (c *Context) Tracef(format string, params ...interface{}) {
	msg := fmt.Sprintf(c.requestID+" "+format, params...)
	// utils.WriteApiLog(c.requestID, "Trace", msg)
	logger.Trace(msg)

}

// Debugf formats message according to format specifier
// and writes to log with level = Debug.
func (c *Context) Debugf(format string, params ...interface{}) {
	msg := fmt.Sprintf(c.requestID+" "+format, params...)
	// utils.WriteApiLog(c.requestID, "Debug", msg)
	logger.Debug(msg)
}

// Infof formats message according to format specifier
// and writes to log with level = Info.
func (c *Context) Infof(format string, params ...interface{}) {
	msg := fmt.Sprintf(c.requestID+" "+format, params...)
	// utils.WriteApiLog(c.requestID, "Info", msg)
	logger.Info(msg)

}

// Warnf formats message according to format specifier
// and writes to log with level = Warn.
func (c *Context) Warnf(format string, params ...interface{}) error {
	msg := fmt.Sprintf(format, params...)
	// utils.WriteApiLog(c.requestID, "Warn", msg)
	logger.Warn(c.requestID, msg)
	return errors.New(msg)
}

// Errorf formats message according to format specifier
// and writes to log with level = Error.
func (c *Context) Errorf(format string, params ...interface{}) error {
	msg := fmt.Sprintf(format, params...)
	// utils.WriteApiLog(c.requestID, "Error", msg)
	logger.Error(msg)
	return errors.New(msg)
}

// Criticalf formats message according to format specifier
// and writes to log with level = Critical.
func (c *Context) Criticalf(format string, params ...interface{}) error {
	msg := fmt.Sprintf(format, params...)
	// utils.WriteApiLog(c.requestID, "Critical", msg)
	logger.Critical(msg)
	return errors.New(msg)
}

// Trace formats message using the default formats for its operands
// and writes to log with level = Trace
func (c *Context) Trace(v ...interface{}) {
	msg := c.requestID + " " + fmt.Sprint(v...)
	// utils.WriteApiLog(c.requestID, "Trace", msg)
	logger.Trace(msg)
}

// Debug formats message using the default formats for its operands
// and writes to log with level = Debug
func (c *Context) Debug(v ...interface{}) {
	msg := c.requestID + " " + fmt.Sprint(v...)
	// utils.WriteApiLog(c.requestID, "Debug", msg)
	logger.Debug(msg)
}

// Info formats message using the default formats for its operands
// and writes to log with level = Info
func (c *Context) Info(v ...interface{}) {
	msg := c.requestID + " " + fmt.Sprint(v...)
	// utils.WriteApiLog(c.requestID, "Info", msg)
	logger.Info(msg)
}

// Warn formats message using the default formats for its operands
// and writes to log with level = Warn
func (c *Context) Warn(v ...interface{}) error {
	msg := fmt.Sprint(v...)
	// utils.WriteApiLog(c.requestID, "Warn", msg)
	logger.Warn(c.requestID + " " + msg)
	return errors.New(msg)
}

// Error formats message using the default formats for its operands
// and writes to log with level = Error
func (c *Context) Error(v ...interface{}) error {
	msg := fmt.Sprint(v...)
	// utils.WriteApiLog(c.requestID, "Error", msg)
	logger.Error(c.requestID + " " + msg)
	return errors.New(msg)
}

// Critical formats message using the default formats for its operands
// and writes to log with level = Critical
func (c *Context) Critical(v ...interface{}) error {
	msg := fmt.Sprint(v...)
	// utils.WriteApiLog(c.requestID, "Critical", msg)
	logger.Critical(c.requestID + " " + msg)
	return errors.New(msg)
}

// H is a shortcup for map[string]interface{}
type H = gin.H

// HandlerFunc api handler
type HandlerFunc func(*Context)

// StdHandlerFunc api handler
type StdHandlerFunc func(*Context) (code int, message string, data interface{})

// RouterGroup wrap gin RouterGroup
type RouterGroup struct {
	routerGroup *gin.RouterGroup
}

// Group creates a new router group. You should add all the routes that have common middlwares or the same path prefix.
// For example, all the routes that use a common middlware for authorization could be grouped.
func (group *RouterGroup) Group(relativePath string, handlers ...HandlerFunc) *RouterGroup {
	return &RouterGroup{
		routerGroup: group.routerGroup.Group(relativePath, wrapHandlers(handlers)...),
	}
}

// BasePath get base path
func (group *RouterGroup) BasePath() string {
	return group.routerGroup.BasePath()
}

// Use adds middleware to the group, see example code in github.
func (group *RouterGroup) Use(handlers ...HandlerFunc) *RouterGroup {
	group.routerGroup.Use(wrapHandlers(handlers)...)
	return group
}

// Handle registers a new request handle and middleware with the given path and method.
// The last handler should be the real handler, the other ones should be middleware that can and should be shared among different routes.
// See the example code in github.
//
// For GET, POST, PUT, PATCH and DELETE requests the respective shortcut
// functions can be used.
//
// This function is intended for bulk loading and to allow the usage of less
// frequently used, non-standardized or custom methods (e.g. for internal
// communication with a proxy).
func (group *RouterGroup) Handle(httpMethod, relativePath string, handlers ...HandlerFunc) *RouterGroup {
	mode := gin.Mode()
	gin.SetMode(gin.ReleaseMode)
	group.routerGroup.Handle(httpMethod, relativePath, wrapHandlers(handlers)...)
	gin.SetMode(mode)

	debugPrintRoute(httpMethod, joinPaths(group.BasePath(), relativePath), handlers)
	return group
}

// POST is a shortcut for router.Handle("POST", path, handle).
func (group *RouterGroup) POST(relativePath string, handlers ...HandlerFunc) *RouterGroup {
	group.Handle("POST", relativePath, handlers...)
	return group
}

// GET is a shortcut for router.Handle("GET", path, handle).
func (group *RouterGroup) GET(relativePath string, handlers ...HandlerFunc) *RouterGroup {
	group.Handle("GET", relativePath, handlers...)
	return group
}

// DELETE is a shortcut for router.Handle("DELETE", path, handle).
func (group *RouterGroup) DELETE(relativePath string, handlers ...HandlerFunc) *RouterGroup {
	group.Handle("DELETE", relativePath, handlers...)
	return group
}

// PATCH is a shortcut for router.Handle("PATCH", path, handle).
func (group *RouterGroup) PATCH(relativePath string, handlers ...HandlerFunc) *RouterGroup {
	group.Handle("PATCH", relativePath, handlers...)
	return group
}

// PUT is a shortcut for router.Handle("PUT", path, handle).
func (group *RouterGroup) PUT(relativePath string, handlers ...HandlerFunc) *RouterGroup {
	group.Handle("PUT", relativePath, handlers...)
	return group
}

// OPTIONS is a shortcut for router.Handle("OPTIONS", path, handle).
func (group *RouterGroup) OPTIONS(relativePath string, handlers ...HandlerFunc) *RouterGroup {
	group.Handle("OPTIONS", relativePath, handlers...)
	return group
}

// HEAD is a shortcut for router.Handle("HEAD", path, handle).
func (group *RouterGroup) HEAD(relativePath string, handlers ...HandlerFunc) *RouterGroup {
	group.Handle("HEAD", relativePath, handlers...)
	return group
}

// Any registers a route that matches all the HTTP methods.
// GET, POST, PUT, PATCH, HEAD, OPTIONS, DELETE, CONNECT, TRACE.
func (group *RouterGroup) Any(relativePath string, handlers ...HandlerFunc) *RouterGroup {
	group.Handle("GET", relativePath, handlers...)
	group.Handle("POST", relativePath, handlers...)
	group.Handle("PUT", relativePath, handlers...)
	group.Handle("PATCH", relativePath, handlers...)
	group.Handle("HEAD", relativePath, handlers...)
	group.Handle("OPTIONS", relativePath, handlers...)
	group.Handle("DELETE", relativePath, handlers...)
	group.Handle("CONNECT", relativePath, handlers...)
	group.Handle("TRACE", relativePath, handlers...)
	return group
}

// StdHandle registers a new request handle and middleware with the given path and method.
// The last handler should be the real handler, the other ones should be middleware that can and should be shared among different routes.
// See the example code in github.
//
// For GET, POST, PUT, PATCH and DELETE requests the respective shortcut
// functions can be used.
//
// This function is intended for bulk loading and to allow the usage of less
// frequently used, non-standardized or custom methods (e.g. for internal
// communication with a proxy).
func (group *RouterGroup) StdHandle(httpMethod, relativePath string, handlers ...StdHandlerFunc) *RouterGroup {
	mode := gin.Mode()
	gin.SetMode(gin.ReleaseMode)
	group.routerGroup.Handle(httpMethod, relativePath, wrapStdHandlers(handlers)...)
	gin.SetMode(mode)

	debugPrintStdRoute(httpMethod, joinPaths(group.BasePath(), relativePath), handlers)
	return group
}

// StdPOST is a shortcut for router.Handle("POST", path, handle).
func (group *RouterGroup) StdPOST(relativePath string, handlers ...StdHandlerFunc) *RouterGroup {
	group.StdHandle("POST", relativePath, handlers...)
	return group
}

// StdGET is a shortcut for router.Handle("GET", path, handle).
func (group *RouterGroup) StdGET(relativePath string, handlers ...StdHandlerFunc) *RouterGroup {
	group.StdHandle("GET", relativePath, handlers...)
	return group
}

// StdDELETE is a shortcut for router.Handle("DELETE", path, handle).
func (group *RouterGroup) StdDELETE(relativePath string, handlers ...StdHandlerFunc) *RouterGroup {
	group.StdHandle("DELETE", relativePath, handlers...)
	return group
}

// StdPATCH is a shortcut for router.Handle("PATCH", path, handle).
func (group *RouterGroup) StdPATCH(relativePath string, handlers ...StdHandlerFunc) *RouterGroup {
	group.StdHandle("PATCH", relativePath, handlers...)
	return group
}

// StdPUT is a shortcut for router.Handle("PUT", path, handle).
func (group *RouterGroup) StdPUT(relativePath string, handlers ...StdHandlerFunc) *RouterGroup {
	group.StdHandle("PUT", relativePath, handlers...)
	return group
}

// StdOPTIONS is a shortcut for router.Handle("OPTIONS", path, handle).
func (group *RouterGroup) StdOPTIONS(relativePath string, handlers ...StdHandlerFunc) *RouterGroup {
	group.StdHandle("OPTIONS", relativePath, handlers...)
	return group
}

// StdHEAD is a shortcut for router.Handle("HEAD", path, handle).
func (group *RouterGroup) StdHEAD(relativePath string, handlers ...StdHandlerFunc) *RouterGroup {
	group.StdHandle("HEAD", relativePath, handlers...)
	return group
}

// StdAny registers a route that matches all the HTTP methods.
// GET, POST, PUT, PATCH, HEAD, OPTIONS, DELETE, CONNECT, TRACE.
func (group *RouterGroup) StdAny(relativePath string, handlers ...StdHandlerFunc) *RouterGroup {
	group.StdHandle("GET", relativePath, handlers...)
	group.StdHandle("POST", relativePath, handlers...)
	group.StdHandle("PUT", relativePath, handlers...)
	group.StdHandle("PATCH", relativePath, handlers...)
	group.StdHandle("HEAD", relativePath, handlers...)
	group.StdHandle("OPTIONS", relativePath, handlers...)
	group.StdHandle("DELETE", relativePath, handlers...)
	group.StdHandle("CONNECT", relativePath, handlers...)
	group.StdHandle("TRACE", relativePath, handlers...)
	return group
}

func wrapHandlers(handlers []HandlerFunc) []gin.HandlerFunc {
	ginHandlers := make([]gin.HandlerFunc, len(handlers))
	for i, h := range handlers {
		ginHandlers[i] = wrapHandler(h)
	}
	return ginHandlers
}

func wrapHandler(h HandlerFunc) gin.HandlerFunc {
	return func(c *gin.Context) {

		requestID := c.GetString(_RequestIDKey)
		if len(requestID) == 0 {
			id := make([]byte, 16)
			rand.Read(id)
			requestID = hex.EncodeToString(id)
			c.Set(_RequestIDKey, requestID)
			c.Writer.Header().Add("X-Request-ID", requestID)
		}
		ctx := &Context{
			Context:   c,
			requestID: requestID,
		}

		defer func() {
			if err := recover(); err != nil {
				if logger != nil {
					stack := stack(1)
					ctx.Errorf("[Recovery] panic recovered:\n%s\n%s", err, stack)
				}
				c.JSON(500, err)
			}
		}()
		if c.GetBool("X-Dumping") {
			h(ctx)
			return
		}
		c.Set("X-Dumping", true)

		dump, err := httputil.DumpRequest(c.Request, false)
		if err != nil {
			c.AbortWithError(http.StatusInternalServerError, err)
			return
		}

		ctx.Infof("Begin API Handler: %s------------------", dump)

		if c.Request.Body != http.NoBody {
			var buf bytes.Buffer
			if _, err = buf.ReadFrom(c.Request.Body); err != nil {
				c.AbortWithError(http.StatusInternalServerError, err)
				return
			}
			if err = c.Request.Body.Close(); err != nil {
				c.AbortWithError(http.StatusInternalServerError, err)
				return
			}
			ctx.Infof("Request: %s\n\n------------------", buf.String())
			c.Request.Body = ioutil.NopCloser(bytes.NewReader(buf.Bytes()))
		}

		responseDumper := &responseDumper{ResponseWriter: c.Writer, outBuffer: bytes.NewBuffer(nil)}
		c.Writer = responseDumper

		h(ctx)
		fmt.Println("::::", responseDumper.bytes())
		ctx.Infof("End API Handler: \n%s\n------------------", responseDumper.bytes())
	}
}

func wrapStdHandlers(handlers []StdHandlerFunc) []gin.HandlerFunc {
	ginHandlers := make([]gin.HandlerFunc, len(handlers))
	for i, h := range handlers {
		ginHandlers[i] = wrapStdHandler(h)
	}
	return ginHandlers
}

func wrapStdHandler(h StdHandlerFunc) gin.HandlerFunc {
	return wrapHandler(func(c *Context) {
		defer func() {
			if err := recover(); err != nil {
				stack := stack(4)
				c.Errorf("panic:\n%s\n%s", err, stack)

				c.Set("code", 500)
				c.JSON(200, gin.H{
					"code":    500,
					"message": fmt.Sprint(err),
					"data":    nil,
				})
			}
		}()

		code, message, data := h(c)
		if code == 0 {
			message = "success"
		}
		c.Set("code", code)
		c.JSON(200, gin.H{
			"code":    code,
			"message": message,
			"data":    data,
		})
	})
}

type responseDumper struct {
	gin.ResponseWriter
	outBuffer *bytes.Buffer
}

func (r *responseDumper) Write(data []byte) (int, error) {
	r.outBuffer.Write(data)
	return r.ResponseWriter.Write(data)
}

func (r *responseDumper) bytes() []byte {
	if r.ResponseWriter.Header().Get("Content-Encoding") == "gzip" {
		return []byte("[gzip data]")
	}
	return r.outBuffer.Bytes()
}

// Last returns the last handler in the chain. ie. the last handler is the main own.
func last(c []HandlerFunc) HandlerFunc {
	if length := len(c); length > 0 {
		return c[length-1]
	}
	return nil
}

func debugPrintRoute(httpMethod, absolutePath string, handlers []HandlerFunc) {
	nuHandlers := len(handlers)
	handlerName := nameOfFunction(last(handlers))
	fmt.Printf("[GIN] %-6s %-25s --> %s (%d handlers)\n", httpMethod, absolutePath, handlerName, nuHandlers)
}

// Last returns the last handler in the chain. ie. the last handler is the main own.
func lastStd(c []StdHandlerFunc) StdHandlerFunc {
	if length := len(c); length > 0 {
		return c[length-1]
	}
	return nil
}

func debugPrintStdRoute(httpMethod, absolutePath string, handlers []StdHandlerFunc) {
	nuHandlers := len(handlers)
	handlerName := nameOfFunction(lastStd(handlers))
	fmt.Printf("[GIN] %-6s %-25s --> %s (%d handlers)\n", httpMethod, absolutePath, handlerName, nuHandlers)
}

func lastChar(str string) uint8 {
	if str == "" {
		panic("The length of the string can't be 0")
	}
	return str[len(str)-1]
}

func nameOfFunction(f interface{}) string {
	return runtime.FuncForPC(reflect.ValueOf(f).Pointer()).Name()
}

func joinPaths(absolutePath, relativePath string) string {
	if relativePath == "" {
		return absolutePath
	}

	finalPath := path.Join(absolutePath, relativePath)
	appendSlash := lastChar(relativePath) == '/' && lastChar(finalPath) != '/'
	if appendSlash {
		return finalPath + "/"
	}
	return finalPath
}

// stack returns a nicely formatted stack frame, skipping skip frames.
func stack(skip int) []byte {
	buf := new(bytes.Buffer) // the returned data
	// As we loop, we open files and read them. These variables record the currently
	// loaded file.
	var lines [][]byte
	var lastFile string
	for i := skip; ; i++ { // Skip the expected number of frames
		pc, file, line, ok := runtime.Caller(i)
		if !ok {
			break
		}
		// Print this much at least.  If we can't find the source, it won't show.
		fmt.Fprintf(buf, "%s:%d (0x%x)\n", file, line, pc)
		if file != lastFile {
			data, err := ioutil.ReadFile(file)
			if err != nil {
				continue
			}
			lines = bytes.Split(data, []byte{'\n'})
			lastFile = file
		}
		fmt.Fprintf(buf, "\t%s: %s\n", function(pc), source(lines, line))
	}
	return buf.Bytes()
}

var (
	dunno     = []byte("???")
	centerDot = []byte("·")
	dot       = []byte(".")
	slash     = []byte("/")
)

// source returns a space-trimmed slice of the n'th line.
func source(lines [][]byte, n int) []byte {
	n-- // in stack trace, lines are 1-indexed but our array is 0-indexed
	if n < 0 || n >= len(lines) {
		return dunno
	}
	return bytes.TrimSpace(lines[n])
}

// function returns, if possible, the name of the function containing the PC.
func function(pc uintptr) []byte {
	fn := runtime.FuncForPC(pc)
	if fn == nil {
		return dunno
	}
	name := []byte(fn.Name())
	// The name includes the path name to the package, which is unnecessary
	// since the file name is already included.  Plus, it has center dots.
	// That is, we see
	//	runtime/debug.*T·ptrmethod
	// and want
	//	*T.ptrmethod
	// Also the package path might contains dot (e.g. code.google.com/...),
	// so first eliminate the path prefix
	if lastslash := bytes.LastIndex(name, slash); lastslash >= 0 {
		name = name[lastslash+1:]
	}
	if period := bytes.Index(name, dot); period >= 0 {
		name = name[period+1:]
	}
	name = bytes.Replace(name, centerDot, dot, -1)
	return name
}

const handlerLogConfig = `
<seelog>
	<outputs>
		<rollingfile formatid="local" type="size" filename="./logs/lmp_server.log" maxsize="134217728" maxrolls="5" />
	</outputs>
	<formats>
		<format id="local" format="%Date %Time [%Level] %File:%Line %Func %Msg%n"/>
	</formats>
</seelog>
`
