// Copyright 2023 The LMP Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// https://github.com/linuxkerneltravel/lmp/blob/develop/LICENSE
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// author: Woa <me@wuzy.cn>

package k8s

import (
	"context"
	"fmt"
	"os"
	"path"

	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
)

func fileExists(filePath string) bool {
	fileInfo, err := os.Stat(filePath)
	if err == nil && fileInfo.IsDir() == false {
		return true
	}
	return false
}

func getDefaultKubeConfigFile() string {
	home, _ := os.UserHomeDir()
	DefaultConfigPaths := [...]string{
		os.Getenv("kubeConfig"),
		os.Getenv("KUBECONFIG"),
		path.Join(home, ".kube/config"),
		"/etc/kubernetes/admin.conf",
		// "/home/runner/.kube/config", // for GitHib Workflow only
	}

	for _, kubeConfig := range DefaultConfigPaths {
		if kubeConfig != "" && fileExists(kubeConfig) {
			return kubeConfig
		}
	}

	return ""
}

// buildClientSet build clientSet by kubeconfig
func buildClientSet(kubeconfig string) (*kubernetes.Clientset, error) {
	config, err := clientcmd.BuildConfigFromFlags("", kubeconfig)
	if err != nil {
		return &kubernetes.Clientset{}, err
	}
	fmt.Println("[INFO] Config loaded from file:", kubeconfig)

	clientSet, err := kubernetes.NewForConfig(config)
	if err != nil {
		return &kubernetes.Clientset{}, err
	}

	return clientSet, nil
}

func getService(clientSet *kubernetes.Clientset, serviceName string, namespace string) (*v1.Service, error) {
	service, err := clientSet.CoreV1().Services(namespace).Get(context.TODO(), serviceName, metav1.GetOptions{})
	if err != nil {
		return nil, err
	}

	return service, nil
}

func getPodsForService(clientSet *kubernetes.Clientset, namespace string, serviceName string) (*v1.PodList, error) {
	service, err := clientSet.CoreV1().Services(namespace).Get(context.TODO(), serviceName, metav1.GetOptions{})
	if err != nil {
		return nil, err
	}

	selector := labels.Set(service.Spec.Selector).AsSelector()
	pods, err := clientSet.CoreV1().Pods(namespace).List(context.TODO(), metav1.ListOptions{
		LabelSelector: selector.String(),
	})
	if err != nil {
		return nil, err
	}

	return pods, nil
}

func GetPodByService(serviceName string, namespace string, kubeConfigFilePath string) (*v1.Service, *v1.PodList, error) {
	if kubeConfigFilePath == "" {
		kubeConfigFilePath = getDefaultKubeConfigFile()
	}

	clientSet, err := buildClientSet(kubeConfigFilePath)
	if err != nil {
		return nil, nil, err
	}

	service, err := getService(clientSet, serviceName, namespace)
	if err != nil {
		return nil, nil, err
	}

	pods, err := getPodsForService(clientSet, namespace, service.Name)
	if err != nil {
		return nil, nil, err
	}

	return service, pods, nil
}
