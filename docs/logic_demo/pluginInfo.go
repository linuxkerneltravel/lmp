package logic

import "errors"

type PState uint32

const (
	PluginSleeping PState = iota
	PluginRunning
	PluginInvalid
)

type PluginInfo struct {
	PluginState PState
	ExecPath  string
	RunTime uint32 // number of minute
}

func (p *PluginInfo) EnterRun(runtime uint32) error {
	if p.PluginState == PluginSleeping {
		p.PluginState = PluginRunning
		p.RunTime = runtime
	} else if p.PluginState == PluginRunning {
		return errors.New("this Plugin Is Running")
	} else if p.PluginState == PluginInvalid {
		return errors.New("this Plugin Is Invalid")
	}
	return nil
}

// 具体的插件执行之后，调用该函数。如果对应文件不能正常运行，标记为Invalid
func (p *PluginInfo) ExitRun(err error) {
	if err != nil {
		p.PluginState = PluginInvalid
	} else {
		p.PluginState = PluginSleeping
	}
	p.RunTime = 0
}