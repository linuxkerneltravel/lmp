package routes

import (
	"github.com/gin-gonic/gin"
	"net/http"
	"refactor/controllers"
	"refactor/logger"
)

func SetupRouter(mode string) *gin.Engine {
	// 设置成发布模式就不会在终端打印日志了
	if mode == gin.ReleaseMode {
		gin.SetMode(gin.ReleaseMode)
	}

	r := gin.New()

	r.Use(logger.GinLogger(), logger.GinRecovery(true))

	// 注册业务路由
	r.POST("/signup", controllers.SignUpHandler)
	r.POST("/login", controllers.LoginHandler)

	r.GET("/ping", func(c *gin.Context) {
		c.String(http.StatusOK, "pong")
	})
	r.NoRoute(func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"msh": "404",
		})
	})
	return r
}
