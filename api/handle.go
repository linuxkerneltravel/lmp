package api

import (
	"github.com/gin-gonic/gin"
)

func init() {
	SetRouterRegister(func(router *RouterGroup) {
		engine := router.Group("/api")

		engine.GET("/ping", Ping)
		engine.POST("/data/collect", do_collect)
	})
}

func do_collect(c *Context) {
	c.JSON(200, gin.H{"message": "do_collect"})
}

func Ping(c *Context) {
	c.JSON(200, gin.H{"message": "pong"})
}
