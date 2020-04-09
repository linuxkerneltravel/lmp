package routers

import (
	"github.com/gin-gonic/gin"

	"net/http"
)


func RegisterRouter(r *gin.Engine) {
	r.GET("/", func(c *gin.Context) {
		c.HTML(http.StatusOK, "mulSelect.html", nil)
	})
	//权限验证

	//初始化路由
	RegisterRouterSys(r)

}
