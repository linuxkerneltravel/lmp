package v1

import (
	"lmp/server/api/v1/ebpfplugins"
	"lmp/server/api/v1/system"
)

type ApiGroup struct {
	SystemApiGroup      system.ApiGroup
	EbpfPluginsApiGroup ebpfplugins.ApiGroup
}

var ApiGroupApp = new(ApiGroup)
