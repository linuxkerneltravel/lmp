package controllers

type Rescode int64

const (
	CodeSuccess         Rescode = 200
	CodeInvalidParam    Rescode = 412
	CodeUserExist       Rescode = 501
	CodeUserNotExist    Rescode = 416
	CodeInvalidPassword Rescode = 406
	CodeServerBusy      Rescode = 500

	CodeInvalidToken Rescode = 407
	CodeNeedLogin    Rescode = 403
)

var codeMsgMap = map[Rescode]string{
	CodeSuccess:         "success",
	CodeInvalidParam:    "Invalid Param",
	CodeUserExist:       "User Exist",
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
