package models

import (
	"fmt"
	"go.uber.org/zap"
	"io/ioutil"
	"lmp/settings"
	"os"
	"strings"
	"sync"
	"time"
)

// Define global slices for storing all plugins
var PluginServices GlobalPluginService
var FileChan chan string

func init() {
	// Init FileChan
	FileChan = make(chan string, 10)
}

type GlobalPluginService struct {
	Plugins []*PluginService
	Lock    sync.Mutex
}

type PluginService struct {
	F    *os.File
	Name string
	Info string
}

// Register plugins
func RegisterPluginService(name string, f *os.File, info string) {
	if name != "api.py" && name != "db_modules.py" && name != "lmp_influxdb.py" && name != "db_modules.pyc" && name != "lmp_influxdb.pyc" {
		if !strings.HasSuffix(name, ".c") {
			PluginServices.Lock.Lock()
			PluginServices.Plugins = append(PluginServices.Plugins, &PluginService{
				F:    f,
				Name: strings.Trim(name, ".py"),
				Info: info,
			})
			PluginServices.Lock.Unlock()
			zap.L().Info("[plugins added] :" + strings.Trim(name, ".py"))
			fmt.Println("[plugins added] :" + strings.Trim(name, ".py"))
		}
	}
}

func UnregisterPluginService(name string) {
	var ps []*PluginService
	PluginServices.Lock.Lock()
	for _, v := range PluginServices.Plugins {
		if v.Name != name {
			ps = append(ps, v)
		}
	}
	PluginServices.Lock.Unlock()
	PluginServices.Plugins = ps
}

// Print the names of all plugins
func PrintPluginService() {
	for _, plugin := range PluginServices.Plugins {
		fmt.Println(plugin.Name)
		fmt.Println(plugin.Info)
		fmt.Println(plugin.F)
	}
}

// BpfScan：Maintenance of global slices
type BpfScan struct {
}

func (b *BpfScan) Init() error {
	// Read the name of the plug-in in the directory
	files, _ := ioutil.ReadDir(settings.Conf.PluginConfig.Path)
	for _, f := range files {
		// Register plugins
		file, _ := os.Open(settings.Conf.PluginConfig.Path + f.Name())
		RegisterPluginService(f.Name(), file, "")
	}
	return nil
}

// Service : Update the system's current plug-in
func (b *BpfScan) Run() {
	go func() {
		for {
			select {
			case fname := <-FileChan:
				file, _ := os.Open(settings.Conf.PluginConfig.Path + fname)
				RegisterPluginService(fname, file, "")
			}
		}
	}()
}

func (b *BpfScan) Watch() {
	ticker := time.NewTicker(time.Second * 3) // 运行时长
	go func() {
		for {
			select {
			case <-ticker.C:
				for _, v := range PluginServices.Plugins {
					if !Exists(settings.Conf.PluginConfig.Path + v.Name) {
						UnregisterPluginService(v.Name)
					}
				}
			}
		}
		ticker.Stop()
	}()
}

func Exists(path string) bool {
	path = path + ".py"
	_, err := os.Stat(path) //os.Stat获取文件信息
	if err != nil {
		if os.IsExist(err) {
			return true
		}
		return false
	}
	return true
}
