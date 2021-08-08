package controllers

import (
	"fmt"

	"github.com/linuxkerneltravel/lmp/logic"
	"github.com/linuxkerneltravel/lmp/models"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

func Collect(c *gin.Context) {
	frontPlugins := new(models.PluginMessage)
	if err := c.ShouldBindJSON(frontPlugins); err != nil {
		zap.L().Error("error in c.ShouldBindJSON(frontPlugins)", zap.Error(err))
		ResponseError(c, CodeInvalidParam)
		return
	}

	if err := logic.DoCollect(frontPlugins); err != nil {
		zap.L().Error("error in logic.DoCollect()", zap.Error(err))
		ResponseError(c, CodeInvalidParam)
		return
	}

	ResponseSuccess(c, fmt.Sprintf("completed"))
}

func QueryIRQ(c *gin.Context) {
	res, err := logic.DoQueryIRQ()
	if err != nil {
		zap.L().Error("ERROR in QueryIRQ():", zap.Error(err))
		ResponseError(c, CodeServerBusy)
		return
	}

	ResponseSuccess(c, res)
}

func QueryCpuUtilize(c *gin.Context) {
	res, err := logic.DoQueryCpuUtilize()
	if err != nil {
		zap.L().Error("ERROR in QueryCpuUtilize():", zap.Error(err))
		ResponseError(c, CodeServerBusy)
		return
	}

	ResponseSuccess(c, res)
}

func QueryPickNext(c *gin.Context) {
	res, err := logic.DoQueryPickNext()
	if err != nil {
		zap.L().Error("ERROR in QueryPickNext():", zap.Error(err))
		ResponseError(c, CodeServerBusy)
		return
	}

	ResponseSuccess(c, res)
}

func QueryTaskSwitch(c *gin.Context) {
	res, err := logic.DoQueryTaskSwitch()
	if err != nil {
		zap.L().Error("ERROR in QueryTaskSwitch():", zap.Error(err))
		ResponseError(c, CodeServerBusy)
		return
	}

	ResponseSuccess(c, res)
}

func QueryHardDiskReadWriteTime(c *gin.Context) {
	res, err := logic.DoQueryHardDiskReadWriteTime()
	if err != nil {
		zap.L().Error("ERROR in QueryHardDiskReadWriteTime():", zap.Error(err))
		ResponseError(c, CodeServerBusy)
		return
	}

	ResponseSuccess(c, res)
}

func QueryWaterMark(c *gin.Context) {
	res, err := logic.DoQueryWaterMark()
	if err != nil {
		zap.L().Error("ERROR in QueryWaterMark():", zap.Error(err))
		ResponseError(c, CodeServerBusy)
		return
	}

	ResponseSuccess(c, res)
}
