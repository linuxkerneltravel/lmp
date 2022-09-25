package response

import "lmp/server/model/ebpfplugins"

type EbpfPluginsResponse struct {
	EbpfPlugins ebpfplugins.EbpfPlugins `json:"ebpfPlugins"`
}
