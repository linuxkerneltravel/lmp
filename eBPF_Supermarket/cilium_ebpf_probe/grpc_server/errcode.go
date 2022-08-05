package main

import (
	"fmt"
	"google.golang.org/grpc/codes"
)

type Error struct {
	code int
	msg  string
}

var _codes = map[int]string{}

func NewError(code int, msg string) *Error {
	if _, ok := _codes[code]; ok {
		panic(fmt.Sprintf("错误码 %d 已经存在，请更换一个", code))
	}
	_codes[code] = msg
	return &Error{code: code, msg: msg}
}

func (e *Error) Error() string {
	return fmt.Sprintf("错误码：%d, 错误信息：%s", e.Code(), e.Msg())
}

func (e *Error) Code() int {
	return e.code
}

func (e *Error) Msg() string {
	return e.msg
}

var (
	Success          = NewError(0, "成功")
	Fail             = NewError(10000000, "内部错误")
	InvalidParams    = NewError(10000001, "无效参数")
	Unauthorized     = NewError(10000002, "认证错误")
	NotFound         = NewError(10000003, "没有找到")
	Unknown          = NewError(10000004, "未知")
	DeadlineExceeded = NewError(10000005, "超出最后截止期限")
	AccessDenied     = NewError(10000006, "访问被拒绝")
	LimitExceed      = NewError(10000007, "访问限制")
	MethodNotAllowed = NewError(10000008, "不支持该方法")
)

func ToRPCCode(code int) codes.Code {
	var statusCode codes.Code
	switch code {
	case Fail.Code():
		statusCode = codes.Internal
	case InvalidParams.Code():
		statusCode = codes.InvalidArgument
	case Unauthorized.Code():
		statusCode = codes.Unauthenticated
	case AccessDenied.Code():
		statusCode = codes.PermissionDenied
	case DeadlineExceeded.Code():
		statusCode = codes.DeadlineExceeded
	case NotFound.Code():
		statusCode = codes.NotFound
	case LimitExceed.Code():
		statusCode = codes.ResourceExhausted
	case MethodNotAllowed.Code():
		statusCode = codes.Unimplemented
	default:
		statusCode = codes.Unknown
	}

	return statusCode
}
