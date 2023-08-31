package acceptance

import (
	"encoding/json"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
	"testing"

	v1 "k8s.io/api/core/v1"

	"github.com/eswzy/eTrafficManager/bpf"
	"github.com/eswzy/eTrafficManager/pkg/k8s"
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
	fmt.Println("Start Sieging")
	// kubectl exec siege -- siege -c 5 -r 20000 http://sisyphe-sfs.default.svc.cluster.local
	out, err := exec.Command("kubectl", "exec", siegePodName, "--", "siege", "-c", "20", "-r", "40000", "http://"+service.Spec.ClusterIPs[0]).Output()
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

	fmt.Printf("Service: %s, Service IP: %s, Ports: %v\n", service.Name, service.Spec.ClusterIPs, service.Spec.Ports)
	fmt.Printf("Pods:\n")
	for _, pod := range pods.Items {
		p := pod.Spec.Containers[0].Ports[0]
		fmt.Printf("- %s, IP: %s, Ports: %v\n", pod.Name, pod.Status.PodIP, strconv.Itoa(int(p.ContainerPort))+"|"+strconv.Itoa(int(p.HostPort))+"|"+string(p.Protocol))
	}

	// Siege service IP before loading program
	resp1, err := siegeService(siegePodName, service)
	if err != nil {
		t.Errorf("Error when sieging service: %s", err)
	}

	programs, err := bpf.LoadProgram()
	defer programs.Close()
	if err != nil {
		fmt.Println("[ERROR] Loading program failed:", err)
		return
	}

	// fmt.Println(service.Spec.ClusterIP, strconv.Itoa(int(service.Spec.Ports[0].Port)))
	programs.InsertServiceItem(service.Spec.ClusterIP, strconv.Itoa(int(service.Spec.Ports[0].Port)), len(pods.Items))
	for i := 0; i < len(pods.Items); i++ {
		// fmt.Println(strconv.Itoa(int(pods.Items[i].Spec.Containers[0].Ports[0].ContainerPort)))
		programs.AutoInsertBackend(service.Spec.ClusterIP, strconv.Itoa(int(service.Spec.Ports[0].Port)), pods.Items[i].Status.PodIP, strconv.Itoa(int(pods.Items[i].Spec.Containers[0].Ports[0].ContainerPort)), i+1, float64(1/float64(len(pods.Items))))
	}

	err = programs.Attach()
	if err != nil {
		fmt.Println("[ERROR] Attaching failed:", err)
	}

	// Siege service IP after loading program
	resp2, err := siegeService(siegePodName, service)
	if err != nil {
		t.Errorf("Error when sieging service: %s", err)
	}

	reductionElapsedTime := resp1.ElapsedTime - resp2.ElapsedTime
	promotionTransactionRate := resp2.TransactionRate - resp1.TransactionRate
	promotionThroughput := resp2.Throughput - resp1.Throughput
	fmt.Printf("Reducing of ElapsedTime:      %13.5f -> %13.5f = %13.5f\n", resp1.ElapsedTime, resp2.ElapsedTime, reductionElapsedTime)
	fmt.Printf("Promotion of TransactionRate: %13.5f -> %13.5f = %13.5f\n", resp1.TransactionRate, resp2.TransactionRate, promotionTransactionRate)
	fmt.Printf("Promotion of Throughput:      %13.5f -> %13.5f = %13.5f\n", resp1.Throughput, resp2.Throughput, promotionThroughput)
}
