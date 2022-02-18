package request

import (
	"lmp/server/model/common/request"
	"lmp/server/model/system"
)

type SysDictionarySearch struct {
	system.SysDictionary
	request.PageInfo
}
