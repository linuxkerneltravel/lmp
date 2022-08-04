package ebpfplugins

import (
	"bufio"
	"context"
	"fmt"
	"lmp/server/model/data_collector/dao"
	"os/exec"
	"syscall"
	"time"

	"lmp/server/global"
	"lmp/server/model/common/request"
	"lmp/server/model/data_collector/logic"
	"lmp/server/model/ebpfplugins"

	"go.uber.org/zap"
)

const linecache = 1

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
		global.GVA_LOG.Error("error in cmd.Start()", zap.Error(err))
		return
	}

	go func() {
		err = cmd.Wait()
		if err != nil {
			global.GVA_LOG.Error("error in cmd.Wait()", zap.Error(err))
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

	/*if err := mysql.GetRestPluginMessageFromDB(pluginName, pluginType, &(bccPlugin.PluginId),
		&(bccPlugin.PluginExecPath), &(bccPlugin.PluginInstruction), &(bccPlugin.PluginState)); err != nil {
		return nil, ErrorGetPluginFailed
	}*/

	return bccPlugin, nil
}

type CbpfPluginFactory struct{}

func (CbpfPluginFactory) CreatePlugin(pluginName string, pluginType string) (Plugin, error) {
	return nil, nil
}

// for single plugin

var pluginPid = make(map[string]int, 10)

func runSinglePlugin(e request.PluginInfo, out *chan bool, errch *chan error) {
	// TODO
	db := global.GVA_DB.Model(&ebpfplugins.EbpfPlugins{})
	var plugin ebpfplugins.EbpfPlugins
	db.Where("id = ?", e.PluginId).First(&plugin)

	cmd := exec.Command("sudo", "python3", "-u", plugin.PluginPath)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		global.GVA_LOG.Error("error in cmd.StdoutPipe", zap.Error(err))
		*errch <- err
	}
	defer stdout.Close()
	go func() {
		scanner := bufio.NewScanner(stdout)
		linechan := make(chan string, linecache)
		var counter int
		var collector dao.TableInfo
		counter = 1
		for scanner.Scan() {
			linechan <- scanner.Text()
			select {
			case line := <-linechan:
				if counter == 1 {
					fmt.Printf("%s-index-%d", line, counter) //todo 仅用于测试环境
					if err, collector = logic.DataCollectorIndex(plugin.PluginName, line); err != nil {
						*errch <- err
					}
					*out <- true
				} else {
					fmt.Printf("%s-rows-%d", line, counter) //todo 仅用于测试环境
					if err := logic.DataCollectorRow(collector, line); err != nil {
						*errch <- err
					}
				}
				if len(*out) >= 1 {
					<-*out
				}
			}
			counter += 1
		}
	}()

	stderr, err := cmd.StderrPipe()
	if err != nil {
		global.GVA_LOG.Error("error in cmd.StderrPipe", zap.Error(err))
		*errch <- err
	}
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
		global.GVA_LOG.Error("error in cmd.Start()", zap.Error(err))
		*errch <- err
	}
	pluginPid[plugin.PluginPath] = cmd.Process.Pid
	err = cmd.Wait()
	if err != nil {
		global.GVA_LOG.Error("error in cmd.Wait()", zap.Error(err))
		*errch <- err
	}
	defer fmt.Printf("Process finished!")
}

func killProcess(path string) {
	if err := syscall.Kill(-pluginPid[path], syscall.SIGKILL); err != nil {
		return
	}
}
