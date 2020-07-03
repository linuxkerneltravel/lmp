package daemon

import (
	_ "fmt"
	"io/ioutil"
	"os"

	"lmp/internal/BPF"
)

func init() {
	//RegisterDaemonService("bpfscan",&BpfScan{})

}

type BpfScan struct {

}

func (b *BpfScan) Init() error {
	return nil
}

func (b *BpfScan) Run() {
	// Read the name of the plug-in in the directory
	files, _ := ioutil.ReadDir("./plugins")
	for _, f := range files {
		// Register plugins
		file,_ := os.Open("./plugins/"+f.Name())
		bpf.RegisterPluginService(f.Name(),file,"")
	}
	bpf.OutputPluginService()
}
