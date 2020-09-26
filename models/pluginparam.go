package models

// ConfigMessage struct
type ConfigMessage struct {
	DispatchingDelay   bool `json:"dispatchingdelay"`
	WaitingQueueLength bool `json:"waitingqueuelength"`
	SoftIrqTime        bool `json:"softirqtime"`
	HardIrqTime        bool `json:"hardirqtime"`
	OnCpuTime          bool `json:"oncputime"`
	Vfsstat            bool `json:"vfsstat"`
	Dcache             bool `json:"dcache"`
	PidFlag            bool `json:"pidflag"`

	// The real pid number
	Pid string `json:"pid"`
	// Store the config above to the 'BpfFilePath'
	BpfFilePath []string `json:"bpfFilePath"`
}
