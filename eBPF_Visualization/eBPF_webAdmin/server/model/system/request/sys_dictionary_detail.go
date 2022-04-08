package request

import (
	"lmp/server/model/common/request"
	"lmp/server/model/system"
)

type SysDictionaryDetailSearch struct {
	system.SysDictionaryDetail
	request.PageInfo
}
