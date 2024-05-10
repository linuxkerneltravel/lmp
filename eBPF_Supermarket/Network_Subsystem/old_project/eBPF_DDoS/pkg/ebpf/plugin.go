package ebpf

type Plugin interface {
	GetProgramIndex() uint32
	Load() error
	Run() error
	Unload() error
}
