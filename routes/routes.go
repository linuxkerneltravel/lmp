package routes

import (
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
	//r.Use(static.Serve("/", static.LocalFile("static", false)))

	//r.LoadHTMLGlob("./static/webview/*")

	//r.Use(static.Serve("/", static.LocalFile("static", false)))
	//r.StaticrFS("/static", http.Dir("static/"))

	//r.LoadHTMLFiles("./static/webview/index.html")
	//r.Static("/static", "./static")

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

	//	c.Header("Content-type", "text/html, charset=utf-8")
	//	//c.String(200, c.File(fmt.Sprintf("%s/index.html", "static")))
	//	//c.File(fmt.Sprintf("%s/index.html", "static"))
	//	c.HTML(200, "index.html", nil)
	//	//c.File(fmt.Sprintf("%s/index.html", "static"))

	r.NoRoute(func(c *gin.Context) {
		c.JSON(http.StatusOK, &controllers.ResponseData{
			Code: 200,
			Msg:  0,
			Data: 0,
		})
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
