package policy

import (
	"fmt"
	"strings"

	v1 "k8s.io/api/core/v1"
	"k8s.io/utils/strings/slices"
)

var sidecarContainerNames = []string{
	"istio-proxy",
	"eswzy-proxy",
}

var sidecarImagesNames = []string{
	"istio/proxyv2",
	"eswzy/sidecar-proxy",
}

var binaryPaths = []string{
	"usr/local/bin/envoy",
	"go/bin/sidecar",
}

// containerNameSidecarPolicy includes sidecar container name filter policy for sidecar discovering
// TODO: support both k8s format and docker native name
func containerNameSidecarPolicy(containerName string) (bool, string) {
	if slices.Contains(sidecarContainerNames, containerName) {
		return true, binaryPaths[slices.Index(sidecarContainerNames, containerName)]
	}
	return false, ""
}

// imageNameSidecarPolicy includes sidecar container image name filter policy for sidecar discovering
func imageNameSidecarPolicy(imageName string) (bool, string) {
	for i, sidecarImagesName := range sidecarImagesNames {
		if strings.Contains(imageName, sidecarImagesName) {
			return true, binaryPaths[i]
		}
	}
	return false, ""
}

// GetSidecarFromContainerStatuses uses hard-coded policy to find sidecar container
func GetSidecarFromContainerStatuses(containerStatuses []v1.ContainerStatus) (v1.ContainerStatus, int, string, error) {
	// judge by container name first
	for i, containerStatus := range containerStatuses {
		isSidecar, path := containerNameSidecarPolicy(containerStatus.Name)
		if isSidecar {
			return containerStatus, i, path, nil
		}
	}

	for i, containerStatus := range containerStatuses {
		isSidecar, path := imageNameSidecarPolicy(containerStatus.Image)
		if isSidecar {
			return containerStatus, i, path, nil
		}
	}

	return v1.ContainerStatus{}, -1, "", fmt.Errorf("no sidecar finding policy was hit")
}

// GetSidecarBinaryRelativePath gets binary file path for sidecar container
func GetSidecarBinaryRelativePath(name string, image string) (string, error) {
	isSidecar, path := containerNameSidecarPolicy(name)
	if isSidecar {
		return path, nil
	}

	isSidecar, path = imageNameSidecarPolicy(image)
	if isSidecar {
		return path, nil
	}

	return "", fmt.Errorf("looks like %s is not a sidecar", name)
}
