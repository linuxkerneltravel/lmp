package logic

import (
	"bufio"
	"context"
	"fmt"
	"mime/multipart"
	"os/exec"
	"syscall"
	"time"

	"github.com/linuxkerneltravel/lmp/models"
	"github.com/linuxkerneltravel/lmp/settings"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

type Plugin interface {
	EnterRun() error
	ExitRun() error
	Run(chan bool, int)
	GetPluginByName() Plugin
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

func (p *PluginBase) GetPluginByName() Plugin {
	// todo:GetPluginByName() method
	return nil
}

func (p *PluginBase) Run(exitChan chan bool, collectTime int) {
	defer func() {
		if err := recover(); err != nil {
			zap.L().Error("error in execute routine, err:", zap.Error(err.(error)))
			fmt.Println("error in execute routine, err:", err)
		}
	}()

	if err := p.EnterRun(); err != nil {
		return
	}

	cmd := exec.Command("sudo", "python3", p.PluginExecPath)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}

	stdout, err := cmd.StdoutPipe()
	defer stdout.Close()
	go func() {
		scanner := bufio.NewScanner(stdout)
		for scanner.Scan() {
			line := scanner.Text()
			fmt.Println(line)
		}
	}()

	stderr, err := cmd.StderrPipe()
	defer stderr.Close()
	go func() {
		scanner := bufio.NewScanner(stderr)
		for scanner.Scan() {
			line := scanner.Text()
			fmt.Println(line)
		}
	}()

	err = cmd.Start()
	if err != nil {
		zap.L().Error("error in cmd.Start()", zap.Error(err))
		return
	}

	go func() {
		err = cmd.Wait()
		if err != nil {
			zap.L().Error("error in cmd.Wait()", zap.Error(err))
			return
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(collectTime)*time.Second)
	defer cancel()

	for {
		select {
		case <-ctx.Done():
			_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
			_ = p.ExitRun()
			exitChan <- true
			return
		}
	}
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
