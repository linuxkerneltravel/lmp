package request

import (
	"lmp/server/model/common/request"
	"lmp/server/model/system"
)

type SysOperationRecordSearch struct {
	system.SysOperationRecord
	request.PageInfo
}
