package service

import (
	"lmp/server/service/ebpfplugins"
	"lmp/server/service/system"
)

type ServiceGroup struct {
	SystemServiceGroup system.ServiceGroup
	EbpfServiceGroup   ebpfplugins.ServiceGroup
}

var ServiceGroupApp = new(ServiceGroup)
