//
// Created by ChenYuZhao on 2020/7/3.
//
package daemon

import (
	"os"

	"lmp/internal/BPF"
)

var FileChan chan string

func init() {
	// Init FileChan
	FileChan = make(chan string, 10)
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
				bpf.RegisterPluginService(fname,file,"")
			}
		}
	}()
}
