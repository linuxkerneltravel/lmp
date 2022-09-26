package data

// Variables for all monitor sub-commands
// All available after `PreRun` procedure
var (
	// configs
	PodName      string
	PodLabel     string
	NameSpace    string
	Kubeconfig   string
	ExporterPort string
	JaegerAgent  string

	// control words
	ForceMinikube bool
	WithSockops   bool
	SidecarMode   string

	// intermediate variables
	NodeName string
)
