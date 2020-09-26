package logic

import (
	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
	"lmp/models"
	"lmp/settings"
	"mime/multipart"
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
