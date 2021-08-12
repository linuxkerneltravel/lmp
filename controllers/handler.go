package controllers

import (
	"fmt"
	"github.com/linuxkerneltravel/lmp/logger"

	"github.com/linuxkerneltravel/lmp/logic"
	"github.com/linuxkerneltravel/lmp/models"

	"github.com/gin-gonic/gin"
)

func Collect(c *gin.Context) {
	frontPlugins := new(models.PluginMessage)
	if err := c.ShouldBindJSON(frontPlugins); err != nil {
		logger.Error("error in c.ShouldBindJSON(frontPlugins)", err)
		ResponseError(c, CodeInvalidParam)
		return
	}

	if err := logic.DoCollect(frontPlugins); err != nil {
		logger.Error("error in logic.DoCollect()", err)
		ResponseError(c, CodeInvalidParam)
		return
	}

	ResponseSuccess(c, fmt.Sprintf("completed"))
}

func QueryIRQ(c *gin.Context) {
	res, err := logic.DoQueryIRQ()
	if err != nil {
		logger.Error("ERROR in QueryIRQ():", err)
		ResponseError(c, CodeServerBusy)
		return
	}

	ResponseSuccess(c, res)
}

func QueryCpuUtilize(c *gin.Context) {
	res, err := logic.DoQueryCpuUtilize()
	if err != nil {
		logger.Error("ERROR in QueryCpuUtilize():", err)
		ResponseError(c, CodeServerBusy)
		return
	}

	ResponseSuccess(c, res)
}

func QueryPickNext(c *gin.Context) {
	res, err := logic.DoQueryPickNext()
	if err != nil {
		logger.Error("ERROR in QueryPickNext():", err)
		ResponseError(c, CodeServerBusy)
		return
	}

	ResponseSuccess(c, res)
}

func QueryTaskSwitch(c *gin.Context) {
	res, err := logic.DoQueryTaskSwitch()
	if err != nil {
		logger.Error("ERROR in QueryTaskSwitch():", err)
		ResponseError(c, CodeServerBusy)
		return
	}

	ResponseSuccess(c, res)
}

func QueryHardDiskReadWriteTime(c *gin.Context) {
	res, err := logic.DoQueryHardDiskReadWriteTime()
	if err != nil {
		logger.Error("ERROR in QueryHardDiskReadWriteTime():", err)
		ResponseError(c, CodeServerBusy)
		return
	}

	ResponseSuccess(c, res)
}

func QueryWaterMark(c *gin.Context) {
	res, err := logic.DoQueryWaterMark()
	if err != nil {
		logger.Error("ERROR in QueryWaterMark():", err)
		ResponseError(c, CodeServerBusy)
		return
	}

	ResponseSuccess(c, res)
}
