package automatic

import (
	"fmt"
	"strconv"
	"testing"
	"time"

	"lmp/eTrafficManager/bpf"
	"lmp/eTrafficManager/pkg/k8s"
	"lmp/eTrafficManager/pkg/metrics"
)

func TestAutomatic(t *testing.T) {
	fmt.Println("Starting...")
	namespace := "default"
	serviceName := "sisyphe-sfs"
	interval := time.Second * 3
	promHost, err := metrics.GetPromHost()
	if err != nil || promHost == "" {
		fmt.Println("[WARNING]", err)
		fmt.Println("[WARNING] Skipping test...")
		return
	}
	cs := metrics.NodeExporterClusterMetrics{Address: promHost}
	err = cs.Update()
	if err != nil {
		fmt.Println("[WARNING]", err)
		fmt.Println("[WARNING] Skipping test...")
		return
	}

	programs, err := bpf.LoadProgram()
	defer programs.Close()
	if err != nil {
		fmt.Println("[ERROR] Loading program failed:", err)
		return
	}
	err = programs.Attach()
	if err != nil {
		fmt.Println("[ERROR] Attaching failed:", err)
	}
	service, pods, err := k8s.GetPodByService(serviceName, namespace, "")
	if err != nil {
		panic(err.Error())
	}

	for {
		programs.InsertServiceItem(service.Spec.ClusterIP, strconv.Itoa(int(service.Spec.Ports[0].Port)), len(pods.Items), bpf.RandomAction)
		fmt.Printf("Service: %s, Service IP: %s, Ports: %v\n", service.Name, service.Spec.ClusterIPs, service.Spec.Ports)
		fmt.Printf("Pods:\n")

		var totalAvailableRate float64

		for _, pod := range pods.Items {
			p := pod.Spec.Containers[0].Ports[0]
			fmt.Printf("- %s, IP: %s, Ports: %v\n", pod.Name, pod.Status.PodIP, strconv.Itoa(int(p.ContainerPort))+"|"+strconv.Itoa(int(p.HostPort))+"|"+string(p.Protocol))
			hostIP := pod.Status.HostIP
			nodeMetric := cs.Query(hostIP).(metrics.NodeExporterNodeMetric)
			fmt.Println(nodeMetric.AvailableRate())
			totalAvailableRate += nodeMetric.AvailableRate()
		}

		totalPercentage := 0.0
		for i := 0; i < len(pods.Items); i++ {
			hostIP := pods.Items[i].Status.HostIP
			nodeMetric := cs.Query(hostIP).(metrics.NodeExporterNodeMetric)
			possibility := nodeMetric.AvailableRate() / totalAvailableRate
			totalPercentage += possibility
			programs.AutoInsertBackend(service.Spec.ClusterIP, strconv.Itoa(int(service.Spec.Ports[0].Port)), pods.Items[i].Status.PodIP, strconv.Itoa(int(pods.Items[i].Spec.Containers[0].Ports[0].ContainerPort)), i+1, possibility, totalPercentage)
		}

		time.Sleep(interval)
		service, pods, err = k8s.GetPodByService(serviceName, namespace, "")
		if err != nil {
			panic(err.Error())
		}
		cs.Update()
		s := bpf.Service{
			IP:   service.Spec.ClusterIPs[0],
			Port: strconv.Itoa(int(service.Spec.Ports[0].Port)),
		}
		programs.AutoDeleteService(s, nil)
	}

}
