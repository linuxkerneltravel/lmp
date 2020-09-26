package controllers

import (
	"fmt"
	"github.com/gin-gonic/gin"
	"lmp/logic"
)

func UpLoadFiles(c *gin.Context) {
	form, err := c.MultipartForm()
	if err != nil {
		ResponseError(c, CodeInvalidParam)
	}

	logic.SavePlugins(form, c)

	ResponseSuccess(c, fmt.Sprintf("plugin uploaded!"))
}
