package k8s

import (
	"fmt"

	"github.com/shirou/gopsutil/v3/process"
	v1 "k8s.io/api/core/v1"

	"github.com/linuxkerneltravel/lmp/eBPF_Supermarket/sidecar/policy"
	"github.com/linuxkerneltravel/lmp/eBPF_Supermarket/sidecar/tools"
)

// PreflightCheck does preflight checks before interacting with k8s
func PreflightCheck(kubeconfig string) (string, string, string, string, error) {
	// 1. Check kubeconfig
	if kubeconfig == "" {
		kubeconfig = tools.GetDefaultKubeConfig()
		if kubeconfig != "" {
			fmt.Printf("[PREFLIGHT] Got default kubeconfig from '%s'\n", kubeconfig)
		}
	} else {
		fmt.Printf("[PREFLIGHT] Got user specified kubeconfig from '%s'\n", kubeconfig)
	}
	if tools.FileExists(kubeconfig) == false {
		if kubeconfig == "" {
			kubeconfig = "(nil)"
		}
		return "", "", "", "", fmt.Errorf("cannot load kubeconfig from: %s", kubeconfig)
	}

	// 2. Get node name
	nodeName, err := tools.GetNodeName()
	if err != nil {
		return kubeconfig, "", "", "", fmt.Errorf("get node name failed: %s", err)
	}
	fmt.Printf("[PREFLIGHT] Got node name '%s'\n", nodeName)

	// 3. Get node container runtime
	nodeContainerRuntime, nodeContainerRuntimeVersion, err := tools.GetNodeContainerRuntime(kubeconfig, nodeName)
	if err != nil {
		return kubeconfig, nodeName, "", "", fmt.Errorf("cannot find out node container runtime from node %s: %s", nodeName, err)
	}
	fmt.Printf("[PREFLIGHT] Got container runtime '%s://%s'\n", nodeContainerRuntime, nodeContainerRuntimeVersion)
	if policy.IsSupportedContainerRuntime(nodeContainerRuntime) == false {
		return kubeconfig, nodeName, nodeContainerRuntime, nodeContainerRuntimeVersion, fmt.Errorf("unsupported container runtime %s://%s for node %s", nodeContainerRuntime, nodeContainerRuntimeVersion, nodeName)
	}

	return kubeconfig, nodeName, nodeContainerRuntime, nodeContainerRuntimeVersion, nil
}

// GetContainersFromPod get containerStatuses from pod spec
func GetContainersFromPod(kubeconfig string, nodeName string, namespace string, podName string) ([]v1.ContainerStatus, error) {
	// 1. Get pod object
	targetPod, err := tools.LocateTargetPod(kubeconfig, podName, namespace)
	if err != nil {
		return nil, fmt.Errorf("locating target pod failed: %s", err)
	}
	fmt.Printf("[INFO] Get target pod '%s' in namesapce '%s' on node '%s'\n", podName, namespace, targetPod.Spec.NodeName)
	if targetPod.Spec.NodeName != nodeName {
		return nil, fmt.Errorf("the pod '%s' is not on local machine, but %s", podName, targetPod.Spec.NodeName)
	}

	// 2. Get container statuses
	containerStatuses, err := tools.GetContainerStatuses(*targetPod)
	if err != nil {
		return nil, fmt.Errorf("getting container statuses failed: %s", err)
	}
	fmt.Printf("[INFO] Get %d container(s) in this pod\n", len(containerStatuses))

	return containerStatuses, nil
}

// GetAllPodProcess get all processes from a pod
func GetAllPodProcess(kubeconfig string, nodeName string, namespace string, podName string) (map[v1.ContainerStatus][]*process.Process, error) {
	// 1. Get all containers
	containerStatuses, err := GetContainersFromPod(kubeconfig, nodeName, namespace, podName)
	if err != nil {
		return nil, err
	}

	res := map[v1.ContainerStatus][]*process.Process{}
	nodeContainerRuntime, _, err := tools.GetNodeContainerRuntime(kubeconfig, nodeName)
	if err != nil {
		return nil, err
	}

	// 2. traverse containerStatuses and get processes
	for _, containerStatus := range containerStatuses {
		processes, err := tools.GetAllProcessFromContainer(containerStatus, nodeContainerRuntime)
		if err != nil {
			return nil, err
		}
		res[containerStatus] = processes
	}

	return res, nil
}

// GetSidecarAndServiceProcess get single sidecar process and single service process
func GetSidecarAndServiceProcess(kubeconfig string, nodeName string, namespace string, podName string) ([]*process.Process, []*process.Process, error) {
	// 1. Get all containers
	containerStatuses, err := GetContainersFromPod(kubeconfig, nodeName, namespace, podName)
	if err != nil {
		return nil, nil, err
	}

	// 2. Get sidecar container and service containers
	sidecarContainerStatus, sidecarContainerIndex, _, err := policy.GetSidecarFromContainerStatuses(containerStatuses)
	if err != nil {
		return nil, nil, fmt.Errorf("sidecar finding failed: %s", err)
	}
	serviceContainerStatuses := append(containerStatuses[:sidecarContainerIndex], containerStatuses[sidecarContainerIndex+1:]...)
	fmt.Printf("[INFO] Got sidecar container '%s' with image '%s'\n", sidecarContainerStatus.Name, sidecarContainerStatus.Image)
	fmt.Printf("[INFO] Got %d service container(s) in this pod\n", len(serviceContainerStatuses))
	if len(serviceContainerStatuses) != 1 {
		return nil, nil, fmt.Errorf("unsupported service container number, perhaps supported in the future")
	}
	serviceContainerStatus := serviceContainerStatuses[0]

	// 3. Get sidecar process and service process
	nodeContainerRuntime, _, err := tools.GetNodeContainerRuntime(kubeconfig, nodeName)
	sidecarProcesses, err := tools.GetAllProcessFromContainer(sidecarContainerStatus, nodeContainerRuntime)
	if err != nil {
		return nil, nil, fmt.Errorf("got sidecar processes failed: %s", err)
	}
	serviceProcesses, err := tools.GetAllProcessFromContainer(serviceContainerStatus, nodeContainerRuntime)
	if err != nil {
		return nil, nil, fmt.Errorf("got service processes failed: %s", err)
	}

	if len(sidecarProcesses) == 0 || len(serviceProcesses) == 0 {
		return nil, nil, fmt.Errorf("unsupported process number '%d' or '%d'", len(sidecarProcesses), len(serviceProcesses))
	}

	fmt.Println("[INFO] Sidecar processes for BPF:", sidecarProcesses)
	fmt.Println("[INFO] Service processes for BPF:", serviceProcesses)

	return sidecarProcesses, serviceProcesses, nil
}
