package controllers

type Rescode int64

const (
	CodeSuccess Rescode = 1000 + iota
	CodeInvalidParam
	CodeUserExist
	CodeUserNotExist
	CodeInvalidPassword
	CodeServerBusy

	CodeInvalidToken
	CodeNeedLogin
)

var codeMsgMap = map[Rescode]string{
	CodeSuccess:         "success",
	CodeInvalidParam:    "Invalid Param",
	CodeUserNotExist:    "User Not Exist",
	CodeInvalidPassword: "Invalid Password",
	CodeServerBusy:      "Server Busy",

	CodeInvalidToken: "Invalid Auth",
	CodeNeedLogin:    "Need Login",
}

func (c Rescode) Msg() string {
	msg, ok := codeMsgMap[c]
	if !ok {
		msg = codeMsgMap[CodeServerBusy]
	}
	return msg
}
