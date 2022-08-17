package ebpfplugins

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"lmp/server/model/data_collector/check"
	"lmp/server/model/data_collector/dao"
	"os/exec"
	"strings"
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

func runSinglePlugin(e request.PluginInfo, out *chan bool, errch *chan error, parameterlist []string) {
	// TODO
	db := global.GVA_DB.Model(&ebpfplugins.EbpfPlugins{})
	var plugin ebpfplugins.EbpfPlugins
	db.Where("id = ?", e.PluginId).First(&plugin)
	cmd := exec.Command("sudo", "python", "-u", plugin.PluginPath)
	if len(parameterlist) > 0 {
		parameter := strings.Join(parameterlist, " ")
		cmd = exec.Command("sudo", "python", "-u", plugin.PluginPath, parameter)
	}
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
		var tableinfo dao.TableInfo
		var indexname string
		var counter int
		default_create_table := true
		counter = 1
		for scanner.Scan() {
			linechan <- scanner.Text()
			select {
			case line := <-linechan:
				if counter == 1 {
					if check.VerifyCompleteIndexFormat(line) {
						err, tableinfo = logic.DataCollectorIndexFromIndex(plugin.PluginName, line)
						if err != nil {
							global.GVA_LOG.Error("error in DataCollectorIndexFromIndex:", zap.Error(err))
							*errch <- err
							return
						}
						default_create_table = false
						global.GVA_LOG.Info("使用用户指定的数据类型建表！")
					} else {
						global.GVA_LOG.Info("使用正则的方式自动建表！")
						indexname = line
					}
					*out <- true
				}
				if counter > 1 {
					if !default_create_table {
						if err := logic.DataCollectorRow(tableinfo, line); err != nil {
							global.GVA_LOG.Error("error in DataCollectorRow:", zap.Error(err))
						}
					}
					if default_create_table {
						if counter == 2 {
							err, tableinfo = logic.DataCollectorIndexFromData(plugin.PluginName, indexname, line)
							if err != nil {
								global.GVA_LOG.Error("error in DataCollectorIndexFromData:", zap.Error(err))
								return
							}
							if err := logic.DataCollectorRow(tableinfo, line); err != nil {
								global.GVA_LOG.Error("error in DataCollectorIndexFromData:", zap.Error(err))
								return
							}
						} else {
							if check.VerifyMultipleDataMatched(line, tableinfo.IndexType) {
								if err := logic.DataCollectorRow(tableinfo, line); err != nil {
									global.GVA_LOG.Error("error in DataCollectorIndexFromData:", zap.Error(err))
									return
								}
							} else {
								if check.IsPossiblyLost(line) {
									global.GVA_LOG.Warn("可能存在数据丢失...")
									continue
								} else {
									mismatcheerr := fmt.Sprintf("第%d行数据无法自动匹配，！", counter)
									fmt.Printf("本行数据内容：%s", line)
									err = errors.New(mismatcheerr)
									global.GVA_LOG.Error("error:\n", zap.Error(err))
									continue
								}
							}
						}
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
