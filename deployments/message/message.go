package message

type ConfigMessage struct {
	DispatchingDelay 		bool	`json:"dispatchingdelay"`
	WaitingQueueLength 		bool	`json:"waitingqueuelength"`
	SoftIrqTime 			bool	`json:"softirqtime"`
	HardIrqTime 			bool	`json:"hardirqtime"`
	OnCpuTime 				bool 	`json:"oncputime"`
}
