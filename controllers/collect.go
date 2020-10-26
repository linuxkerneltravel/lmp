package controllers

import (
	_ "context"
	"fmt"
	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
	"lmp/logic"
	"lmp/models"
	//"strconv"
	_ "time"
)

func Collect(c *gin.Context) {
	// 1、填充表单数据，得到所有的参数
	//m := fillFrontMessage(c)
	//fmt.Println("I am here", m)

	p := new(models.ConfigMessage)
	if err := c.ShouldBindJSON(p); err != nil {
		zap.L().Error("Login with invalid param", zap.Error(err))
		ResponseError(c, CodeInvalidParam)
		return
	}

	//fmt.Println("p is here", p)
	// 2、得到当前的用户名，之后利用这个用户名作为influxdb的dbname
	dbname, err := getCurrentUsername(c)
	if err != nil {
		zap.L().Error("error in getCurrentUsername()", zap.Error(err))
	}
	// 3、把dbname作为一个参数和填充好的表单数据一块下发给logic层
	if err := logic.DoCollect(*p, dbname); err != nil {
		zap.L().Error("error in logic.DoCollect()", zap.Error(err))
	}

	//ResponseRediect(c, settings.Conf.GrafanaConfig.IP)

	ResponseSuccess(c, fmt.Sprintf("collecting..."))
}
