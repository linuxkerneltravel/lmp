package http

import (
	"github.com/gin-gonic/gin"
	"github.com/urfave/cli"
)
// RouterGroup wrap gin RouterGroup
type RouterGroup struct {
	routerGroup *gin.RouterGroup
}

func init() {
	SetRouterRegister(func(router *RouterGroup) {
	})
}


var routerRegisters []func(*RouterGroup)

// SetRouterRegister 设置路由注册器
func SetRouterRegister(reg func(group *RouterGroup)) {
	routerRegisters = append(routerRegisters, reg)
}

// NewServer create server
func NewServer(config *cli.Context) *gin.Engine {
	r := gin.Default()

	mode := config.String("mode")
	switch mode {
	case "debug":
		gin.SetMode(gin.DebugMode)
	case "test":
		gin.SetMode(gin.TestMode)
	case "release":
		gin.SetMode(gin.ReleaseMode)
	default:
		gin.SetMode(gin.DebugMode)
	}

	for _, reg := range routerRegisters {
		reg(&RouterGroup{
			routerGroup: &r.RouterGroup,
		})
	}
	return r
}