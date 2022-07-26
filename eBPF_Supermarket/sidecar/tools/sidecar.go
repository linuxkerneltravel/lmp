package tools

import (
	"fmt"
	"github.com/eswzy/podstat/policy"
	"path"
	"strings"
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
	containerName := ""
	if strings.Contains(containerInfo.Name, "istio-proxy") {
		containerName = "istio-proxy"
	} else if strings.Contains(containerInfo.Name, "eswzy-proxy") {
		containerName = "eswzy-proxy"
	}

	binaryPath, err := policy.GetSidecarBinaryRelativePath(containerName, "")
	if err != nil {
		return "", err
	}

	return path.Join(rootPath, binaryPath), nil
}
