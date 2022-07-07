package policy

import "k8s.io/utils/strings/slices"

// supportedRuntimes
var supportedRuntimes = []string{
	"docker",
	// "containerd", // TODO: waiting for test
}

// IsSupportedContainerRuntime judges whether this runtime is supported
func IsSupportedContainerRuntime(runtime string) bool {
	return slices.Contains(supportedRuntimes, runtime)
}
