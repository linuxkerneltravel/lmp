package router

import (
	"lmp/server/router/ebpfplugins"
	"lmp/server/router/system"
)

type RouterGroup struct {
	System      system.RouterGroup
	EbpfPlugins ebpfplugins.RouterGroup
}

var RouterGroupApp = new(RouterGroup)
