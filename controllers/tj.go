package controllers

import (
	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
	"lmp/logic"
)

func QueryIRQ(c *gin.Context) {
	res, err := logic.DoQueryIRQ()
	if err != nil {
		zap.L().Error("ERROR in QueryIRQ():", zap.Error(err))
		ResponseError(c, CodeServerBusy)
		return
	}

	ResponseSuccess(c, res)
}
