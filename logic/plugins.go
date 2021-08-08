package logic

import (
	"bufio"
	"context"
	"fmt"
	"github.com/linuxkerneltravel/lmp/dao/mysql"
	"go.uber.org/zap"
	"os/exec"
	"syscall"
	"time"
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
	PluginType        string
	PluginExecPath    string
	PluginInstruction string
	PluginState       bool
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
	CreatePlugin(string, string) (Plugin, error)
}

type BccPluginFactory struct{}

func (BccPluginFactory) CreatePlugin(pluginName string, pluginType string) (Plugin, error) {
	bccPlugin := BccPlugin{}
	bccPlugin.PluginBase = new(PluginBase)

	bccPlugin.PluginName = pluginName
	bccPlugin.PluginType = pluginType

	if err := mysql.GetRestPluginMessageFromDB(pluginName, pluginType, &(bccPlugin.PluginId),
		&(bccPlugin.PluginExecPath), &(bccPlugin.PluginInstruction), &(bccPlugin.PluginState)); err != nil {
		return nil, ErrorGetPluginFailed
	}

	return bccPlugin, nil
}

type CbpfPluginFactory struct{}

func (CbpfPluginFactory) CreatePlugin(pluginName string, pluginType string) (Plugin, error) {
	return nil, nil
}
