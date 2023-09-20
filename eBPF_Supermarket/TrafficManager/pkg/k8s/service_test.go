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
	"fmt"
	"strconv"
	"testing"
)

func TestGetPodsForService(t *testing.T) {
	namespace := "default"
	serviceName := "sisyphe-sfs"

	service, pods, err := GetPodByService(serviceName, namespace, "")
	if err != nil {
		panic(err.Error())
	}

	fmt.Printf("Service: %s, Service IP: %s, Ports: %v\n", service.Name, service.Spec.ClusterIPs, service.Spec.Ports)
	fmt.Printf("Pods:\n")
	for _, pod := range pods.Items {
		p := pod.Spec.Containers[0].Ports[0]
		fmt.Printf("- %s, IP: %s, Ports: %v\n", pod.Name, pod.Status.PodIP, strconv.Itoa(int(p.ContainerPort))+"|"+strconv.Itoa(int(p.HostPort))+"|"+string(p.Protocol))
	}
}
