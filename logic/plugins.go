package logic

import (
	"github.com/gin-gonic/gin"
	"github.com/linuxkerneltravel/lmp/models"
	"github.com/linuxkerneltravel/lmp/settings"
	"go.uber.org/zap"
	"mime/multipart"
)

type Plugin interface {
	EnterRun()
	ExitRun()
	Run()
}

type PluginBase struct {
	PluginState bool
	ExecPath    string
	Runtime     uint32
}

func (p *PluginBase) EnterRun() {

}

func (p *PluginBase) ExitRun() {

}

type CbpfPlugin struct {
	*PluginBase
}

func (p *CbpfPlugin) Run() {

}

type BccPlugin struct {
	*PluginBase
}

func (p *BccPlugin) Run() {

}

type PluginFactory interface {
	CreatePlugin(string, uint32) Plugin
}

type BccPluginFactory struct{}

func (BccPluginFactory) CreatePlugin(execPath string, runTime uint32) Plugin {
	return &BccPlugin{
		PluginBase: &PluginBase{
			PluginState: false,
			ExecPath:    execPath,
			Runtime:     runTime,
		},
	}
}

type CbpfPluginFactory struct{}

func (CbpfPluginFactory) CreatePlugin(execPath string, runTime uint32) Plugin {
	return &CbpfPlugin{
		PluginBase: &PluginBase{
			PluginState: false,
			ExecPath:    execPath,
			Runtime:     runTime,
		},
	}
}

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
