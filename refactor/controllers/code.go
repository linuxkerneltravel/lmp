package controllers

type Rescode int64

const (
	CodeSuccess Rescode = 1000 + iota
	CodeInvalidParam
	CodeUserExist
	CodeUserNotExist
	CodeInvalidPassword
	CodeServerBusy
)

var codeMsgMap = map[Rescode]string{
	CodeSuccess:         "success",
	CodeInvalidParam:    "Invalid Param",
	CodeUserNotExist:    "User Not Exist",
	CodeInvalidPassword: "Invalid Password",
	CodeServerBusy:      "Server Busy",
}

func (c Rescode) Msg() string {
	msg, ok := codeMsgMap[c]
	if !ok {
		msg = codeMsgMap[CodeServerBusy]
	}
	return msg
}
