package tools

import (
	"fmt"
	"path"
	"strings"

	"github.com/linuxkerneltravel/lmp/eBPF_Supermarket/sidecar/policy"
)

func GetSidecarBinaryPath(containerID string, runtime string) (string, error) {
	rootPath, err := GetContainerFileSystemRoot(containerID, runtime)
	if err != nil {
		return "", fmt.Errorf("got container file system root failed: %s", err)
	}

	containerInfo, err := GetDockerContainerInfo(containerID)
	if err != nil {
		return "", err
	}

	// fix the container name, as same as sidecarContainerNames in policy pkg
	// FIXME: make this enumerable or configurable
	containerName := ""
	if strings.Contains(containerInfo.Name, "istio-proxy") {
		containerName = "istio-proxy"
	} else if strings.Contains(containerInfo.Name, "sidecar-proxy") {
		containerName = "sidecar-proxy"
	}

	binaryPath, err := policy.GetSidecarBinaryRelativePath(containerName, "")
	if err != nil {
		return "", err
	}

	return path.Join(rootPath, binaryPath), nil
}
