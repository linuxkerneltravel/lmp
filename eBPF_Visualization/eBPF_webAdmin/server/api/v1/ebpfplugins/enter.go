package ebpfplugins

import "lmp/server/service"

type ApiGroup struct {
	EbpfPluginsApi
}

var (
	ebpfService = service.ServiceGroupApp.EbpfServiceGroup.EbpfpluginsService
)
