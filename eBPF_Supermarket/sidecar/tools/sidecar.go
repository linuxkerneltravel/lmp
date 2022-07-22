package tools

import (
	"fmt"
	"github.com/eswzy/podstat/policy"
	"path"
)

func GetSidecarBinaryPath(containerID string, runtime string) (string, error) {
	rootPath, err := GetContainerFileSystemRoot(containerID, runtime)
	if err != nil {
		return "", fmt.Errorf("got container file system root failed: %s", err)
	}

	//containerInfo, err := GetDockerContainerInfo(containerID)
	//if err != nil {
	//	return "", err
	//}

	// TODO: fix the container name
	binaryPath, err := policy.GetSidecarBinaryRelativePath("istio-proxy", "")
	if err != nil {
		return "", err
	}

	return path.Join(rootPath, binaryPath), nil
}
