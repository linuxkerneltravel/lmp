package response

import "lmp/server/config"

type SysConfigResponse struct {
	Config config.Server `json:"config"`
}
