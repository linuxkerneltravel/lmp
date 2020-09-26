package models

import (
	"fmt"
	"io/ioutil"
	"os"
	"strings"
)

// Define global slices for storing all plugins
var PluginServices []*PluginService
var FileChan chan string

func init() {
	// Read the name of the plug-in in the directory
	files, _ := ioutil.ReadDir("./plugins")
	for _, f := range files {
		// Register plugins
		file,_ := os.Open("./plugins/"+f.Name())
		RegisterPluginService(f.Name(),file,"")
	}

	// Init FileChan
	FileChan = make(chan string, 10)
}

type PluginService struct {
	F *os.File
	Name string
	Info string
}

// Register plugins
func RegisterPluginService(name string, f *os.File, info string) {
	if name != "api.py" && name != "db_modules.py" && name != "lmp_influxdb.py" && name != "db_modules.pyc" && name != "lmp_influxdb.pyc" {
		if !strings.HasSuffix(name,".c"){
			PluginServices = append(PluginServices, &PluginService{
				F : f,
				Name : strings.Trim(name, ".py"),
				Info : info,
			})
			fmt.Println("[plugins] :" + strings.Trim(name, ".py"))
		}
	}
}

// Print the names of all plugins
func PrintPluginService() {
	for _,plugin := range PluginServices {
		fmt.Println(plugin.Name)
		fmt.Println(plugin.Info)
		fmt.Println(plugin.F)
	}
}

type BpfScan struct {

}

func (b *BpfScan) Init() error {

	return nil
}

// Service : Update the system's current plug-in
func (b *BpfScan) Run() {
	go func() {
		for {
			select {
			case fname := <- FileChan:
				file,_ := os.Open("./plugins/" + fname)
				RegisterPluginService(fname,file,"")
			}
		}
	}()
}
