package logic

import (
	"mime/multipart"

	"github.com/gin-gonic/gin"
	"github.com/linuxkerneltravel/lmp/models"
	"github.com/linuxkerneltravel/lmp/settings"
	"go.uber.org/zap"
)

func SavePlugins(form *multipart.Form, c *gin.Context) (err error) {
	files := form.File["bpffile"]

	for _, file := range files {
		zap.L().Info(file.Filename)
		c.SaveUploadedFile(file, settings.Conf.PluginConfig.Path+file.Filename)
		// Put the name of the newly uploaded plug-in into the global pipeline Filename
		models.FileChan <- file.Filename
	}

	return nil
}

func GetAllplugins() (pluginsName []string) {
	for _, plugin := range models.PluginServices.Plugins {
		pluginsName = append(pluginsName, plugin.Name)
	}

	return pluginsName
}
