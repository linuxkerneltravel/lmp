package logic

import (
	"github.com/gin-gonic/gin"
	"github.com/linuxkerneltravel/lmp/models"
	"github.com/linuxkerneltravel/lmp/settings"
	"go.uber.org/zap"
	"mime/multipart"
)

type Plugin interface {
	EnterRun() error
	ExitRun() error
	Run(chan bool, int)
}

type PluginBase struct {
	PluginId          int
	PluginName        string
	PluginState       bool
	PluginExecPath    string
	PluginInstruction string
}

func (p *PluginBase) EnterRun() error {
	// todo:update Mysql
	return nil
}

func (p *PluginBase) ExitRun() error {
	// todo:update Mysql
	return nil
}

func (p *PluginBase) Run(exitChan chan bool, runtime int) {
	// todo:Run method
	return
}

type CbpfPlugin struct {
	*PluginBase
}

type BccPlugin struct {
	*PluginBase
}

type PluginFactory interface {
	CreatePlugin(string, uint32) Plugin
}

type BccPluginFactory struct{}

func (BccPluginFactory) CreatePlugin(id int, name string, execPath string, instruction string) Plugin {
	return &BccPlugin{
		PluginBase: &PluginBase{
			PluginId:          id,
			PluginName:        name,
			PluginState:       false,
			PluginExecPath:    execPath,
			PluginInstruction: instruction,
		},
	}
}

type CbpfPluginFactory struct{}

func (CbpfPluginFactory) CreatePlugin(id int, name string, execPath string, instruction string) Plugin {
	return &CbpfPlugin{
		PluginBase: &PluginBase{
			PluginId:          id,
			PluginName:        name,
			PluginState:       false,
			PluginExecPath:    execPath,
			PluginInstruction: instruction,
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
