package routes

import (
	"fmt"
	"net/http"

	"github.com/linuxkerneltravel/lmp/controllers"
	"github.com/linuxkerneltravel/lmp/logger"

	"github.com/gin-gonic/contrib/static"
	"github.com/gin-gonic/gin"
)

func SetupRouter(mode string) *gin.Engine {
	if mode == gin.ReleaseMode {
		gin.SetMode(gin.ReleaseMode)
	}

	r := gin.New()
	r.Use(cors())
	r.Use(logger.GinLogger(), logger.GinRecovery(true))
	r.Use(static.Serve("/", static.LocalFile("static", false)))
	r.StaticFS("/static", http.Dir("static/"))

	r.GET("/ping", func(c *gin.Context) {
		c.String(http.StatusOK, "pong")
	})

	r.POST("/collectdata", controllers.Collect)

	r.GET("/irq_delay", controllers.QueryIRQ)
	r.GET("/cpu_utilize", controllers.QueryCpuUtilize)
	r.GET("/pick_next", controllers.QueryPickNext)
	r.GET("/task_switch", controllers.QueryTaskSwitch)
	r.GET("/harddisk_readwritetime", controllers.QueryHardDiskReadWriteTime)
	r.GET("/water_mark", controllers.QueryWaterMark)

	r.NoRoute(func(c *gin.Context) {
		c.Header("Content-Type", "text/html,charset=utf-8")
		c.File(fmt.Sprintf("%s/index.html", "static"))
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
