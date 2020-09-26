package logic

import (
	"fmt"
	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
	"lmp/models"
	"mime/multipart"
)

func SavePlugins(form *multipart.Form, c *gin.Context) (err error) {
	// todo :  Multiple files uploaded
	PluginPath := "./plugins/"
	files := form.File["bpffile"]
	fmt.Println("file:", files)
	fmt.Println(PluginPath)

	for _, file := range files {
		zap.L().Info(file.Filename)
		c.SaveUploadedFile(file, PluginPath + file.Filename)
		// Put the name of the newly uploaded plug-in into the pipeline Filename
		models.FileChan <- file.Filename
	}

	return nil
}
