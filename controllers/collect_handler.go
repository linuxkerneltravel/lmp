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

	plugins := new(logic.PluginStorage)
	plugins, err := plugins.CreatePluginStorage(frontPlugins)
	if err != nil {
		zap.L().Error("error in plugins.CreatePluginStorage(frontPlugins)", zap.Error(err))
		ResponseError(c, CodeInvalidParam)
		return
	}

	if err = logic.DoCollect(plugins); err != nil {
		zap.L().Error("error in logic.DoCollect()", zap.Error(err))
		ResponseError(c, CodeInvalidParam)
		return
	}

	ResponseSuccess(c, fmt.Sprintf("completed"))
}
