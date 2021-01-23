package models

// ConfigMessage struct
type ConfigMessage struct {
	Data Configure `json:"data"`
	// time
	CollectTime int `json:"collecttime"`
	//BpfFilePath []string `json:"bpfFilePath"`
}

type Configure struct {
	Cpuutilize            bool `json:"cpuutilize"`
	Irq                   bool `json:"irq"`
	Taskswitch            bool `json:"taskswitch"`
	Picknext              bool `json:"picknext"`
	Harddiskreadwritetime bool `json:"harddiskreadwritetime"`
	Memusage              bool `json:"memusage"`
}
