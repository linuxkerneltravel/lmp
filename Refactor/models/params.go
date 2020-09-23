package models

// 定义请求的参数结构体

/*
	gin 框架使用了 validator 库，要在下面的结构体里面添加上tag，gin 中使用 validator 用的是 binding

	binding:"required" 代表 ：需要
*/
type ParamSignUp struct {
	Username   string `json:"username" binding:"required"`
	Password   string `json:"password" binding:"required"`
	RePassword string `json:"re_password" binding:"required,eqfield=Password"` // eqfield=Password表示这个字段必须和Password相等
}
