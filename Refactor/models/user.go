package models

// User 注册请求参数
type User struct {
	UserID   int64  `db:"user_id"`
	Username string `db:"username"`
	Password string `db:"password"`
}

// ParamLogin 登录请求参数
type ParamLogin struct {
	Username string `db:"username"`
	Password string `db:"password"`
}
