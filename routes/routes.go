package routes

import (
	"fmt"
	"github.com/gin-gonic/contrib/static"
	"github.com/gin-gonic/gin"
	"lmp/controllers"
	"net/http"

	"lmp/logger"
	"lmp/middlewares"
)

func SetupRouter(mode string) *gin.Engine {
	if mode == gin.ReleaseMode {
		gin.SetMode(gin.ReleaseMode)
	}

	r := gin.New()
	r.Use(cors())
	r.Use(logger.GinLogger(), logger.GinRecovery(true))
	//r := gin.Default()
	r.Use(static.Serve("/", static.LocalFile("static", false)))
	r.StaticFS("/static", http.Dir("static/"))
	//r.Use(static.Serve("/", static.LocalFile("webview", false)))
	//r.StaticFS("/webview", http.Dir("webview/"))

	r.GET("/ping", func(c *gin.Context) {
		c.String(http.StatusOK, "pong")
	})
	r.POST("/signup", controllers.SignUpHandler)
	r.POST("/login", controllers.LoginHandler)

	r.POST("/uploadfiles", middlewares.JWTAuthMiddleware(), controllers.UpLoadFiles)
	r.GET("/allplugins", middlewares.JWTAuthMiddleware(), controllers.PrintAllplugins)
	r.POST("/data/collect", middlewares.JWTAuthMiddleware(), controllers.Collect)

	// for tianjin
	r.GET("/irq_delay", controllers.QueryIRQ)
	r.GET("/cpu_utilize", controllers.QueryCpuUtilize)
	r.GET("/pick_next", controllers.QueryPickNext)
	r.GET("/task_switch", controllers.QueryTaskSwitch)
	r.GET("/harddisk_readwritetime", controllers.QueryHardDiskReadWriteTime)
	r.GET("/water_mark", controllers.QueryWaterMark)

	// Logicals that require login
	// r.POST("/uploadfiles", middlewares.JWTAuthMiddleware(), controllers.UpLoadFiles)

	r.NoRoute(func(c *gin.Context) {
		c.File(fmt.Sprintf("%s/login.html", "static"))
	})

	return r
}

// 跨域中间件
func cors() gin.HandlerFunc {
	return func(c *gin.Context) {
		origin := c.Request.Header.Get("origin")
		if len(origin) == 0 {
			origin = c.Request.Header.Get("Origin")
		}
		c.Writer.Header().Set("Access-Control-Allow-Origin", origin)
		c.Writer.Header().Set("Access-Control-Allow-Credentials", "true")
		c.Writer.Header().Set("Access-Control-Allow-Headers", "Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization, accept, origin, Cache-Control, X-Requested-With")
		c.Writer.Header().Set("Access-Control-Allow-Methods", "OPTIONS, GET, POST")
		c.Writer.Header().Set("Content-Type", "application/json; charset=utf-8")
		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(204)
			return
		}
		c.Next()
	}
}
