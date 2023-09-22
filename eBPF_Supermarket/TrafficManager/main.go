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

package main

import (
	"flag"
	"fmt"
	"strconv"
	"time"

	"lmp/eTrafficManager/bpf"
	"lmp/eTrafficManager/pkg/k8s"
)

func main() {
	namespace := flag.String("namespace", "default", "namespace of service")
	serviceName := flag.String("service", "sisyphe", "name of service")
	kubeconfig := flag.String("kubeconfig", "", "path of config")
	duration := flag.Duration("duration", time.Minute*10, "duration for this program to run")
	flag.Parse()

	if *serviceName == "" {
		fmt.Println("[ERROR] Empty service name!")
		return
	}

	service, pods, err := k8s.GetPodByService(*serviceName, *namespace, *kubeconfig)
	if err != nil {
		panic(err.Error())
	}

	fmt.Printf("Got Service: %s, Service IP: %s, Ports: %v\n", service.Name, service.Spec.ClusterIPs, service.Spec.Ports)
	fmt.Printf("Got Pods:\n")
	for _, pod := range pods.Items {
		p := pod.Spec.Containers[0].Ports[0]
		fmt.Printf("- %s, IP: %s, Ports: %v\n", pod.Name, pod.Status.PodIP, strconv.Itoa(int(p.ContainerPort))+"|"+strconv.Itoa(int(p.HostPort))+"|"+string(p.Protocol))
	}

	programs, err := bpf.LoadProgram()
	defer programs.Close()
	if err != nil {
		fmt.Println("[ERROR] Loading program failed:", err)
		return
	}

	programs.InsertServiceItem(service.Spec.ClusterIP, strconv.Itoa(int(service.Spec.Ports[0].Port)), len(pods.Items), bpf.RandomAction)
	defer programs.AutoDeleteService(bpf.Service{
		IP:   service.Spec.ClusterIP,
		Port: strconv.Itoa(int(service.Spec.Ports[0].Port)),
	}, nil)

	totalPercentage := 0.0
	for i := 0; i < len(pods.Items); i++ {
		totalPercentage += 1 / float64(len(pods.Items))
		programs.AutoInsertBackend(service.Spec.ClusterIP, strconv.Itoa(int(service.Spec.Ports[0].Port)), pods.Items[i].Status.PodIP, strconv.Itoa(int(pods.Items[i].Spec.Containers[0].Ports[0].ContainerPort)), i+1, 1/float64(len(pods.Items)), totalPercentage)
	}

	err = programs.Attach()
	if err != nil {
		fmt.Println("[ERROR] Attaching failed:", err)
	}
	time.Sleep(*duration)
}
