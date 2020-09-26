package middlewares

import (
	"github.com/gin-gonic/gin"
	"lmp/controllers"
	"lmp/pkg/jwt"
	"strings"
)

func JWTAuthMiddleware() func(c *gin.Context) {
	return func(c *gin.Context) {
		authHeader := c.Request.Header.Get("Authorization")
		if authHeader == "" {
			controllers.ResponseError(c, controllers.CodeNeedLogin)
			c.Abort()
			return
		}

		parts := strings.SplitN(authHeader, " ", 2)
		if !(len(parts) == 2 && parts[0] == "Bearer") {
			controllers.ResponseError(c, controllers.CodeInvalidToken)
			c.Abort()
			return
		}

		mc, err := jwt.ParseToken(parts[1])
		if err != nil {
			controllers.ResponseError(c, controllers.CodeInvalidToken)
			c.Abort()
			return
		}

		c.Set(controllers.CtxtUserIDKey, mc.UserID)
		c.Next() // 后续的处理函数可以用过c.Get(CtxtUserIDKey)来获取当前请求的用户信息
	}
}
