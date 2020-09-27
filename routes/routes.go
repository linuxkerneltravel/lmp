package routes

import (
	"fmt"
	"github.com/gin-gonic/contrib/static"
	"github.com/gin-gonic/gin"
	"lmp/controllers"
	"net/http"

	"lmp/logger"
)

func SetupRouter(mode string) *gin.Engine {
	if mode == gin.ReleaseMode {
		gin.SetMode(gin.ReleaseMode)
	}

	r := gin.New()
	r.Use(logger.GinLogger(), logger.GinRecovery(true))
	r.Use(static.Serve("/", static.LocalFile("static", false)))
	r.StaticFS("/static", http.Dir("static/"))

	r.GET("/ping", func(c *gin.Context) {
		c.String(http.StatusOK, "pong")
	})
	r.POST("/signup", controllers.SignUpHandler)
	r.POST("/login", controllers.LoginHandler)
	r.POST("/uploadfiles", controllers.UpLoadFiles)
	r.GET("/allplugins", controllers.PrintAllplugins)
	r.POST("/data/collect", controllers.Collect)

	// Logicals that require login
	// r.POST("/uploadfiles", middlewares.JWTAuthMiddleware(), controllers.UpLoadFiles)

	r.NoRoute(func(c *gin.Context) {
		c.File(fmt.Sprintf("%s/index.html", "static"))
	})

	return r
}
