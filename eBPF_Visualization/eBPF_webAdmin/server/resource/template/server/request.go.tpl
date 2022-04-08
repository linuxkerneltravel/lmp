package request

import (
	"lmp/server/model/autocode"
	"lmp/server/model/common/request"
)

type {{.StructName}}Search struct{
    autocode.{{.StructName}}
    request.PageInfo
}