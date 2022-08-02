package tools

import (
	"context"
	"fmt"
	"strings"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/client"
	"github.com/shirou/gopsutil/v3/process"
	v1 "k8s.io/api/core/v1"
)

func GetDockerContainerInfo(containerID string) (types.ContainerJSON, error) {
	cli, err := client.NewClientWithOpts(client.FromEnv)
	if err != nil {
		return types.ContainerJSON{}, err
	}

	containerInfo, err := cli.ContainerInspect(context.TODO(), containerID)
	if err != nil {
		return types.ContainerJSON{}, err
	}
	return containerInfo, nil
}

// findInitPid gets myProcess ID of the initial myProcess
func findInitPid(containerID string, runtime string) (int, error) {
	if runtime == "docker" {
		containerInfo, err := GetDockerContainerInfo(containerID)
		if err != nil {
			return -1, err
		}

		// FIXME: get real PID for minikube docker container
		// ref: cgroups golang library (https://github.com/containerd/cgroups), systemd-cgls(1) and IsInMinikubeMode()
		return containerInfo.State.Pid, nil
	}

	return -1, fmt.Errorf("unsupported container runtime '%s'", runtime)
}

// GetAllProcessFromContainer get all processes from one container
func GetAllProcessFromContainer(containerStatus v1.ContainerStatus, nodeContainerRuntime string) ([]*process.Process, error) {
	containerID := containerStatus.ContainerID
	if strings.Contains(containerID, nodeContainerRuntime+"://") {
		containerID = strings.Replace(containerID, nodeContainerRuntime+"://", "", -1)
	} else { // double check
		return nil, fmt.Errorf("unsupported ContainerID '%s'\n", containerID)
	}

	initPid, err := findInitPid(containerID, nodeContainerRuntime)
	if err != nil {
		return nil, err
	}

	fmt.Println("[INFO] Found pid", initPid, "from container", containerID)
	initProcess, err := process.NewProcess(int32(initPid))
	if err != nil {
		return nil, err
	}

	childProcesses, err := FindChildProcesses(initProcess)
	if err != nil {
		fmt.Printf("[INFO] No child process founded for container %s\n", containerID)
	}

	resProcesses := append([]*process.Process{initProcess}, childProcesses...)
	return resProcesses, nil
}

// GetContainerFileSystemRoot get root path on the local machine file system
func GetContainerFileSystemRoot(containerID string, runtime string) (string, error) {
	if runtime == "docker" {
		containerInfo, err := GetDockerContainerInfo(containerID)
		if err != nil {
			return "", err
		}

		return containerInfo.GraphDriver.Data["MergedDir"], nil
	}

	return "", fmt.Errorf("unsupported container runtime '%s'", runtime)
}
