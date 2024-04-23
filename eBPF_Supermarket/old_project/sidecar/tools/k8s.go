package tools

import (
	"context"
	"fmt"
	"os"
	"path"
	"strings"

	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
)

// GetDefaultKubeConfig gets default kubeconfig file path
func GetDefaultKubeConfig() string {
	// get kubeconfig path in this order: env, path ~/.kube/, path /etc/
	DefaultConfigPaths := [...]string{
		os.Getenv("kubeconfig"),
		os.Getenv("KUBECONFIG"),
		path.Join(os.Getenv("HOME"), ".kube/config"),
		"/etc/kubernetes/admin.conf",
	}

	for _, kubeconfig := range DefaultConfigPaths {
		if kubeconfig != "" && FileExists(kubeconfig) {
			return kubeconfig
		}
	}

	return ""
}

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

// GetNodeContainerRuntime gets container runtime version
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

// GetPodNameFromNodeAndLabel finds target pod by node name and label
func GetPodNameFromNodeAndLabel(kubeconfig string, namespace string, nodeName string, labelSelector string) (string, error) {
	clientset, err := buildClientset(kubeconfig)
	if err != nil {
		return "", err
	}

	pod, err := clientset.CoreV1().Pods(namespace).List(context.TODO(), metav1.ListOptions{LabelSelector: labelSelector, FieldSelector: "spec.nodeName=" + nodeName})
	if len(pod.Items) == 1 {
		return pod.Items[0].Name, nil
	}

	return "", fmt.Errorf("pod number is not 1, but %d", len(pod.Items))
}

// LocateTargetPod finds target pod by name and namespace
func LocateTargetPod(kubeconfig string, podName string, namespace string) (*v1.Pod, error) {
	clientset, err := buildClientset(kubeconfig)
	if err != nil {
		return &v1.Pod{}, err
	}

	targetPod, err := clientset.CoreV1().Pods(namespace).Get(context.TODO(), podName, metav1.GetOptions{})

	// pod not found
	if errors.IsNotFound(err) {
		return nil, fmt.Errorf("pod '%s' in namespace '%s' not found\n", podName, namespace)
	}

	// other errors
	if err != nil {
		return nil, err
	}

	return targetPod, nil
}

// GetContainerStatuses gets all container statuses from pod object
func GetContainerStatuses(targetPod v1.Pod) ([]v1.ContainerStatus, error) {
	// pod not running
	if targetPod.Status.Phase != v1.PodRunning {
		return nil, fmt.Errorf("pod not running")
	}

	return targetPod.Status.ContainerStatuses, nil
}

// IsInMinikubeMode returns ture if running on minikube
func IsInMinikubeMode() bool {
	if os.Getenv("MINIKUBE_STARTED") == "TRUE" {
		return true
	}
	return false
}
