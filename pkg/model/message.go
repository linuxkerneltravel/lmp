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
type UserModel struct {
	Username      string `form:"username"`
	Password      string `form:"password"`
	PasswordAgain string `form:"password-again"`
}
