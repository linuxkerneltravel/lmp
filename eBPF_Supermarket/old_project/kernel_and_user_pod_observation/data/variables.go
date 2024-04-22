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

	ImageName    string

	//for grpc
	GrpcPodName   string
	GrpcImageName string
	VEthName	 string


	// control words
	ForceMinikube bool
	WithSockops   bool
	SidecarMode   string

	// intermediate variables
	NodeName     string
	PrometheusIP string
)
