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
	// 1、获取参数和参数校验 ---- 这个应该放在 controller 里面处理
	// 前后端分离，是JSON格式的数据，所以使用 c.ShouldBind() 方法;  如果不是前后端分离，就使用 c.Query()  c.Param()
	// 然后就需要定义请求参数的结构体，在models文件夹下定义一个 params.go，专门用来定义参数结构体。
	p := new(models.ParamSignUp)
	// todo:参数校验输出错误的时候把英文翻译成英文，validator库参数校验若干实用技巧
	if err := c.ShouldBindJSON(p); err != nil { // 只能检测请求的格式、类型对不对
		zap.L().Error("SignUp with invalid param", zap.Error(err))
		ResponseError(c, CodeInvalidParam)
		return
	}
	// 手动对请求参数进行详细的业务
	//if len(p.Username) == 0 || len(p.Password) == 0 || len(p.RePassword) == 0 || p.Password != p.RePassword {
	//	zap.L().Error("SignUp with invalid param")
	//	c.JSON(http.StatusOK, gin.H{
	//		"message": "请求参数有误",
	//	})
	//	return
	//}
	/*
		gin 框架在进行参数校验的时候，已经使用了 github.com/go-playground/validator 这个库，所以我们在
		进行参数校验的时候，就使用这个库就可以了。

		要进行校验的参数定义在 params.go 中，要在定义参数的结构体后面加上tag，就可以实现参数校验了
	*/

	// 2、业务处理 ---- logic 层
	// 一般创建的就返回错误，如果是 查询的就返回的是数据了
	if err := logic.SignUp(p); err != nil {
		if errors.Is(err, mysql.ErrorUserExist) {
			zap.L().Error("SignUp with User Exists", zap.Error(err))
			ResponseError(c, CodeUserExist)
		}
		ResponseError(c, CodeServerBusy)
		return
	}

	// 3、返回响应
	ResponseSuccess(c, nil)
}

func LoginHandler(c *gin.Context) {
	// 1、接收参数并校验参数
	p := new(models.ParamLogin)
	if err := c.ShouldBindJSON(p); err != nil {
		zap.L().Error("Login with invalid param", zap.Error(err))
		ResponseError(c, CodeInvalidParam)
		return
	}
	// 2、业务逻辑处理
	if err := logic.Login(p); err != nil {
		zap.L().Error("logic.Login failed", zap.Error(err))
		if errors.Is(err, mysql.ErrorUserExist) {
			ResponseError(c, CodeUserNotExist)
		}
		ResponseError(c, CodeServerBusy)
	}
	// 3、返回响应
	ResponseSuccess(c, nil)
}
