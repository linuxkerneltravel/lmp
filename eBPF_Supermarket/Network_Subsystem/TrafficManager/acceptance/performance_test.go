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

package acceptance

import (
	"encoding/json"
	"fmt"
	"log"
	"os/exec"
	"strconv"
	"strings"
	"testing"

	v1 "k8s.io/api/core/v1"

	"lmp/eTrafficManager/bpf"
	"lmp/eTrafficManager/pkg/k8s"
)

type SiegeResponse struct {
	Transactions           int     `json:"transactions"`
	Availability           float64 `json:"availability"`
	ElapsedTime            float64 `json:"elapsed_time"`
	DataTransferred        float64 `json:"data_transferred"`
	ResponseTime           float64 `json:"response_time"`
	TransactionRate        float64 `json:"transaction_rate"`
	Throughput             float64 `json:"throughput"`
	Concurrency            float64 `json:"concurrency"`
	SuccessfulTransactions int     `json:"successful_transactions"`
	FailedTransactions     int     `json:"failed_transactions"`
	LongestTransaction     float64 `json:"longest_transaction"`
	ShortestTransaction    float64 `json:"shortest_transaction"`
}

func siegeService(siegePodName string, service *v1.Service) (*SiegeResponse, error) {
	log.Println("Start Sieging")
	// kubectl exec siege -- siege -c 5 -r 20000 http://sisyphe-sfs.default.svc.cluster.local
	out, err := exec.Command("kubectl", "exec", siegePodName, "--", "siege", "-c", "20", "-r", "30000", "http://"+service.Spec.ClusterIPs[0]).Output()
	if err != nil {
		return nil, err
	}
	var resp SiegeResponse
	outString := string(out)
	outString = strings.Replace(outString, "New configuration template added to /root/.siege\nRun siege -C to view the current settings in that file", "", 1)
	fmt.Println(outString)
	err = json.Unmarshal([]byte(outString), &resp)
	return &resp, err
}

func TestServicePerformance(t *testing.T) {
	namespace := "default"
	serviceName := "sisyphe"
	siegePodName := "siege"

	service, pods, err := k8s.GetPodByService(serviceName, namespace, "")
	if err != nil {
		panic(err.Error())
	}

	log.Printf("Service: %s, Service IP: %s, Ports: %v\n", service.Name, service.Spec.ClusterIPs, service.Spec.Ports)
	log.Println("Pods:")
	for _, pod := range pods.Items {
		p := pod.Spec.Containers[0].Ports[0]
		log.Printf("- %s, IP: %s, Ports: %v\n", pod.Name, pod.Status.PodIP, strconv.Itoa(int(p.ContainerPort))+"|"+strconv.Itoa(int(p.HostPort))+"|"+string(p.Protocol))
	}

	// Siege service IP before loading program
	resp1, err := siegeService(siegePodName, service)
	if err != nil {
		t.Errorf("Error when sieging service: %s", err)
	}

	programs, err := bpf.LoadProgram()
	defer programs.Close()
	if err != nil {
		t.Errorf("[ERROR] Loading program failed: %s", err)
		return
	}

	// fmt.Println(service.Spec.ClusterIP, strconv.Itoa(int(service.Spec.Ports[0].Port)))
	programs.InsertServiceItem(service.Spec.ClusterIP, strconv.Itoa(int(service.Spec.Ports[0].Port)), len(pods.Items), bpf.RandomAction)
	totalPercentage := 0.0
	for i := 0; i < len(pods.Items); i++ {
		// fmt.Println(strconv.Itoa(int(pods.Items[i].Spec.Containers[0].Ports[0].ContainerPort)))
		totalPercentage += 1 / float64(len(pods.Items))
		programs.AutoInsertBackend(service.Spec.ClusterIP, strconv.Itoa(int(service.Spec.Ports[0].Port)), pods.Items[i].Status.PodIP, strconv.Itoa(int(pods.Items[i].Spec.Containers[0].Ports[0].ContainerPort)), i+1, 1/float64(len(pods.Items)), totalPercentage)
	}

	err = programs.Attach()
	if err != nil {
		t.Errorf("[ERROR] Attaching failed: %s", err)
	}

	// Siege service IP after loading program
	resp2, err := siegeService(siegePodName, service)
	if err != nil {
		t.Errorf("Error when sieging service: %s", err)
	}

	reductionElapsedTime := resp1.ElapsedTime - resp2.ElapsedTime
	promotionTransactionRate := resp2.TransactionRate - resp1.TransactionRate
	promotionThroughput := resp2.Throughput - resp1.Throughput
	log.Printf("Reducing of ElapsedTime:      %13.5f -> %13.5f = %13.5f\n", resp1.ElapsedTime, resp2.ElapsedTime, reductionElapsedTime)
	log.Printf("Promotion of TransactionRate: %13.5f -> %13.5f = %13.5f\n", resp1.TransactionRate, resp2.TransactionRate, promotionTransactionRate)
	log.Printf("Promotion of Throughput:      %13.5f -> %13.5f = %13.5f\n", resp1.Throughput, resp2.Throughput, promotionThroughput)
}
