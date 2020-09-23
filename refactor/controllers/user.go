package controllers

import (
	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
	"refactor/dao/mysql"
	"refactor/logic"
	"refactor/models"
)

// SignUPHandler 函数处理注册请求
func SignUpHandler(c *gin.Context) {
	p := new(models.ParamSignUp)
	// todo:参数校验输出错误的时候把英文翻译成英文，validator库参数校验若干实用技巧
	if err := c.ShouldBindJSON(p); err != nil { // 只能检测请求的格式、类型对不对
		zap.L().Error("SignUp with invalid param", zap.Error(err))
		ResponseError(c, CodeInvalidParam)
		return
	}

	if err := logic.SignUp(p); err != nil {
		if errors.Is(err, mysql.ErrorUserExist) {
			zap.L().Error("SignUp with User Exists", zap.Error(err))
			ResponseError(c, CodeUserExist)
		}
		ResponseError(c, CodeServerBusy)
		return
	}

	ResponseSuccess(c, nil)
}

func LoginHandler(c *gin.Context) {
	p := new(models.ParamLogin)
	if err := c.ShouldBindJSON(p); err != nil {
		zap.L().Error("Login with invalid param", zap.Error(err))
		ResponseError(c, CodeInvalidParam)
		return
	}

	if err := logic.Login(p); err != nil {
		zap.L().Error("logic.Login failed", zap.Error(err))
		if errors.Is(err, mysql.ErrorUserExist) {
			ResponseError(c, CodeUserNotExist)
		}
		ResponseError(c, CodeServerBusy)
	}

	ResponseSuccess(c, nil)
}
