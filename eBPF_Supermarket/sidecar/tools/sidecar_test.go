package tools

import (
	"fmt"
	"strings"
	"testing"

	"github.com/eswzy/podstat/policy"
	"github.com/eswzy/podstat/test"
)

func TestGetSidecarBinaryPath(t *testing.T) {
	kubeconfig := GetDefaultKubeConfig()
	nodeName := test.NodeName
	namespace := test.Namespace
	label := test.Label
	podName, err := GetPodNameFromNodeAndLabel(kubeconfig, namespace, nodeName, label)

	// podName = "sidecar-demo"
	// namespace = "sidecar"

	targetPod, err := LocateTargetPod(kubeconfig, podName, namespace)
	if err != nil {
		t.Errorf("locating target pod failed: %s", err)
	}
	fmt.Printf("[INFO] Get target pod '%s' in namesapce '%s' on node '%s'\n", podName, namespace, targetPod.Spec.NodeName)
	if targetPod.Spec.NodeName != nodeName {
		t.Errorf("the pod '%s' is not on local machine, but %s", podName, targetPod.Spec.NodeName)
	}

	// 2. Get container statuses
	containerStatuses, err := GetContainerStatuses(*targetPod)
	if err != nil {
		t.Errorf("getting container statuses failed: %s", err)
	}
	fmt.Printf("[INFO] Get %d container(s) in this pod\n", len(containerStatuses))

	sidecarContainerStatus, _, _, err := policy.GetSidecarFromContainerStatuses(containerStatuses)

	if strings.Contains(sidecarContainerStatus.ContainerID, "docker"+"://") {
		containerID := strings.Replace(sidecarContainerStatus.ContainerID, "docker"+"://", "", -1)

		res, err := GetSidecarBinaryPath(containerID, "docker")
		if err != nil {
			t.Errorf("test failed for GetSidecarBinaryPath for: %s", err)
		}
		fmt.Println("-----------Got res-----------")
		fmt.Println(res)
		fmt.Println("-----------------------------")
	} else { // double check
		t.Errorf("unsupported ContainerID '%s'\n", sidecarContainerStatus.ContainerID)
	}

}
