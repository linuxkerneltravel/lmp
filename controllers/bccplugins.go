package controllers

import (
	"fmt"

	"github.com/gin-gonic/gin"
	"github.com/linuxkerneltravel/lmp/logic"
)

func UpLoadFiles(c *gin.Context) {
	form, err := c.MultipartForm()
	if err != nil {
		ResponseError(c, CodeInvalidParam)
	}

	logic.SavePlugins(form, c)

	ResponseSuccess(c, fmt.Sprintf("plugin uploaded!"))
}

func PrintAllplugins(c *gin.Context) {
	allPlugins := logic.GetAllplugins()

	ResponseSuccess(c, allPlugins)
}
