package policy

import (
	"fmt"
	"strings"

	v1 "k8s.io/api/core/v1"
	"k8s.io/utils/strings/slices"
)

var sidecarContainerNames = []string{
	"istio-proxy",
}

var sidecarImagesNames = []string{
	"istio/proxyv2",
}

// containerNameSidecarPolicy includes sidecar container name filter policy for sidecar discovering
func containerNameSidecarPolicy(containerName string) bool {
	if slices.Contains(sidecarContainerNames, containerName) {
		return true
	}
	return false
}

// imageNameSidecarPolicy includes sidecar container image name filter policy for sidecar discovering
func imageNameSidecarPolicy(imageName string) bool {
	for _, sidecarImagesName := range sidecarImagesNames {
		if strings.Contains(imageName, sidecarImagesName) {
			return true
		}
	}
	return false
}

// GetSidecarFromContainerStatuses uses hard-coded policy to fine sidecar container
func GetSidecarFromContainerStatuses(containerStatuses []v1.ContainerStatus) (v1.ContainerStatus, int, error) {
	// judge by container name first
	for i, containerStatus := range containerStatuses {
		if containerNameSidecarPolicy(containerStatus.Name) {
			return containerStatus, i, nil
		}
	}

	for i, containerStatus := range containerStatuses {
		if imageNameSidecarPolicy(containerStatus.Image) {
			return containerStatus, i, nil
		}
	}

	return v1.ContainerStatus{}, -1, fmt.Errorf("no sidecar finding policy was hit")
}
