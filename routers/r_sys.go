package routers

import (
	"github.com/gin-gonic/gin"
	"lmp_ui/deployments/sys"
)

func RegisterRouterSys(r *gin.Engine) {
	data := sys.Data{}
	r.POST("/data/collect", data.Collect)
	//r.POST("/data/display")
}