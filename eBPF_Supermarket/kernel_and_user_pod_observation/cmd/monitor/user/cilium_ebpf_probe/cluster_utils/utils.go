package cluster_utils

import (
	"context"
	"fmt"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"strings"

	"github.com/docker/docker/client"
	"github.com/shirou/gopsutil/v3/process"
)

func GetNodeContainerRuntime(clientset *kubernetes.Clientset, nodeName string) (string, string, error) {

	// get node information

	node, err := clientset.CoreV1().Nodes().Get(context.TODO(), nodeName, metav1.GetOptions{})
	if err != nil {
		return "", "", err
	}
	// myProcess container runtime version string
	res := strings.Split(node.Status.NodeInfo.ContainerRuntimeVersion, "://")
	if len(res) == 2 {
		containerRuntimeKind, containerRuntimeVersion := res[0], res[1]
		return containerRuntimeKind, containerRuntimeVersion, nil
	} else {
		return "", "", fmt.Errorf("unsupported container runtime version: %s", node.Status.NodeInfo.ContainerRuntimeVersion)
	}

}

// findInitPid gets myProcess ID of the initial myProcess
func findInitPid(containerID string, runtime string) (int, error) {
	if runtime == "docker" {
		cli, err := client.NewClientWithOpts(client.FromEnv)
		if err != nil {
			return 0, err
		}

		containerInfo, err := cli.ContainerInspect(context.TODO(), containerID)
		if err != nil {
			return -1, err
		}

		// FIXME: get real PID for minikube docker container
		// ref: cgroups golang library (https://github.com/containerd/cgroups), systemd-cgls(1) and IsInMinikubeMode()
		return containerInfo.State.Pid, nil
	}

	return -1, fmt.Errorf("unsupported container runtime '%s'", runtime)
}
func findELFPath(containerID string, runtime string) (string, error) {
	if runtime == "docker" {
		cli, err := client.NewClientWithOpts(client.FromEnv)
		if err != nil {
			return "", err
		}
		containerInfo, err := cli.ContainerInspect(context.TODO(), containerID)
		if err != nil {
			return "", err
		}
		return containerInfo.GraphDriver.Data["MergedDir"], nil
	}

	return "", fmt.Errorf("unsupported container runtime '%s'", runtime)
}
func FindChildProcesses(parentProcess *process.Process) ([]*process.Process, error) {
	childrenProcess, err := parentProcess.Children()
	if err != nil {
		return nil, err
	}

	return childrenProcess, nil
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

// GetAllPodProcess get all processes from a pod
func GetAllPodProcess(clientset *kubernetes.Clientset, nodeName string, namespace string, podName string, cs []v1.ContainerStatus, img string) (map[v1.ContainerStatus][]*process.Process, error) {
	// 1. Get all containers
	containerStatuses := cs

	res := map[v1.ContainerStatus][]*process.Process{}
	nodeContainerRuntime, _, err := GetNodeContainerRuntime(clientset, nodeName)
	if err != nil {
		return nil, err
	}

	// 2. traverse containerStatuses and get processes

	for _, containerStatus := range containerStatuses {

		if containerStatus.Image == img {
			processes, err := GetAllProcessFromContainer(containerStatus, nodeContainerRuntime)
			fmt.Println("get specific docker of image ", img)
			if err != nil {
				return nil, err
			}
			res[containerStatus] = processes
		}
	}

	return res, nil
}

//GetPodELFPath get the path of the elf path to attach uprobe on
func GetPodELFPath(clientset *kubernetes.Clientset, nodeName string, namespace string, podName string, cs []v1.ContainerStatus, img string) (map[v1.ContainerStatus]string, error) {
	// 1. Get all containers

	containerStatuses := cs
	nodeContainerRuntime, _, err := GetNodeContainerRuntime(clientset, nodeName)
	if err != nil {
		return nil, err
	}
	res := make(map[v1.ContainerStatus]string)

	// 2. traverse containerStatuses and get processes
	for _, containerStatus := range containerStatuses {
		if containerStatus.Image == img {
			fmt.Println("get specific docker of image ", img)
			containerID := containerStatus.ContainerID
			if strings.Contains(containerID, nodeContainerRuntime+"://") {
				containerID = strings.Replace(containerID, nodeContainerRuntime+"://", "", -1)
			} else { // double check
				return nil, fmt.Errorf("unsupported ContainerID '%s'\n", containerID)
			}

			path, err := findELFPath(containerID, nodeContainerRuntime)
			if err != nil {
				return nil, err
			}
			res[containerStatus] = path
		}

	}
	return res, nil
}
