//
// Created by ChenYuZhao
//
package model

// ConfigMessage struct
type ConfigMessage struct {
	DispatchingDelay   bool   `json:"dispatchingdelay"`
	WaitingQueueLength bool   `json:"waitingqueuelength"`
	SoftIrqTime        bool   `json:"softirqtime"`
	HardIrqTime        bool   `json:"hardirqtime"`
	OnCpuTime          bool   `json:"oncputime"`
	Pid                string `json:"pid"`
	Vfsstat            bool   `json:"vfsstat"`
}


//用于用户登录注册
//目前参数只有用户名和密码，后续迭代添加
type UserModel struct {
	Username      string `form:"username"`
	Password      string `form:"password"`
	//Gin 对于数据校验使用的是 validator.v8 库，该库提供多种校验方法。通过 binding:"" 方式来进行对数据的校验。
	//官方文档：https://godoc.org/gopkg.in/go-playground/validator.v9
	PasswordAgain string `form:"password-again" binding:"eqfield=Password"`
}
