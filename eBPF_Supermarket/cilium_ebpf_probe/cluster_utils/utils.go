package cluster_utils

import (
	"context"
	"fmt"
	"github.com/docker/docker/client"
	"github.com/shirou/gopsutil/v3/process"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
	"strings"
)

// getContainersFromPod get containerStatuses from pod spec
// GetNodeContainerRuntime gets container runtime version
// buildClientset build clientset by kubeconfig
func buildClientset(kubeconfig string) (*kubernetes.Clientset, error) {
	// use the current context in kubeconfig
	config, err := clientcmd.BuildConfigFromFlags("", kubeconfig)
	if err != nil {
		return &kubernetes.Clientset{}, err
	}

	// create the clientset
	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return &kubernetes.Clientset{}, err
	}

	return clientset, nil
}

func GetNodeContainerRuntime(kubeconfig string, nodeName string) (string, string, error) {
	clientset, err := buildClientset(kubeconfig)
	if err != nil {
		return "", "", err
	}

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
func GetAllPodProcess(kubeconfig string, nodeName string, namespace string, podName string, cs []v1.ContainerStatus) (map[v1.ContainerStatus][]*process.Process, error) {
	// 1. Get all containers
	containerStatuses := cs

	res := map[v1.ContainerStatus][]*process.Process{}
	nodeContainerRuntime, _, err := GetNodeContainerRuntime(kubeconfig, nodeName)
	if err != nil {
		return nil, err
	}

	// 2. traverse containerStatuses and get processes
	for _, containerStatus := range containerStatuses {
		processes, err := GetAllProcessFromContainer(containerStatus, nodeContainerRuntime)
		if err != nil {
			return nil, err
		}
		res[containerStatus] = processes
	}

	return res, nil
}
