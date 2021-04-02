package logic

type Plugin interface {
	Run(runtime uint32)
}

type CbpfPlugin struct {
	PluginInfo
}

type BccPlugin struct {
	PluginInfo
}

type ShellPlugin struct {
	PluginInfo
}

func (c *CbpfPlugin) Run(runtime uint32) {
	err := c.EnterRun(runtime)
	if err != nil {
		// 前期检查未通过
		return
	}
	// 填充C插件的具体执行:在执行文件时给err赋值，判断文件是否可以正常运行

	c.ExitRun(err)
}

func (b *BccPlugin) Run(runtime uint32) {
	err := b.EnterRun(runtime)
	if err != nil {
		// 前期检查未通过
		return
	}
	// 填充BCC的具体执行: 在执行文件时给err赋值，判断文件是否可以正常运行

	b.ExitRun(err)
}

func (s *ShellPlugin) Run(runtime uint32) {
	err := s.EnterRun(runtime)
	if err != nil {
		// 前期检查未通过
		return
	}
	// 填充Shell的具体执行: 在执行文件时给err赋值，判断文件是否可以正常运行

	s.ExitRun(err)
}
