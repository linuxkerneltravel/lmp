package models

// ConfigMessage struct
type ConfigMessage struct {
	Cpuutilize   bool `json:"cpuutilize"`
	Irq          bool `json:"irq"`
	Memusage     bool `json:"memusage"`
	Picknexttask bool `json:"picknexttask"`
	Runqlen      bool `json:"runqlen"`
	Vfsstat      bool `json:"vfsstat"`
	Dcache       bool `json:"dcache"`

	// Store the config above to the 'BpfFilePath'
	BpfFilePath []string `json:"bpfFilePath"`
	// time
	CollectTime int `json:"collecttime"`
}
