package main

import (
	"flag"
	"fmt"
	"os"
	"strconv"
	"time"

	"github.com/shirou/gopsutil/v3/host"

	"github.com/eswzy/podstat/k8s"
	"github.com/eswzy/podstat/perf/net"
	"github.com/eswzy/podstat/test"
	"github.com/eswzy/podstat/tools"
	"github.com/eswzy/podstat/visualization"
)

func main() {
	uptime, _ := host.Uptime()
	net.TimeOffset = net.TimeOffset.Add(-time.Duration(uptime * 1000000000))

	visualization.VisPort = "8765"
	go visualization.Vis()

	kubeconfig := flag.String("kubeconfig", "", "path to the kubeconfig file")
	podName := flag.String("pod", "", "name of the pod to inspect")
	namespace := flag.String("namespace", "default", "namespace for this pod")
	jaegerAgent := flag.String("jaeger", "", "Jaeger IP and port")
	flag.Parse()

	if *jaegerAgent == "" {
		visualization.JaegerAgentHostPort = os.Getenv("VISUALIZE_IP") + ":" + "6831"
	} else {
		visualization.JaegerAgentHostPort = *jaegerAgent
	}

	if tools.IsInMinikubeMode() {
		minikubePid := os.Getenv("MINIKUBE_ROOT_PID")
		minikubePidInt, err := strconv.Atoi(minikubePid)
		if err != nil {
			fmt.Println("[ERROR] MINIKUBE_ROOT_PID load failed:", minikubePid)
			os.Exit(1)
		}
		fmt.Println("[INFO] Minikube root pid:", minikubePidInt)
		tools.MinikubePid = minikubePidInt
	}

	if *podName == "" {
		// TODO: testing code, delete it after the test
		// https://istio.io/latest/docs/setup/getting-started/
		tmpKubeconfig := tools.GetDefaultKubeConfig()
		fmt.Printf("[DEV] Get kubeconfig: %s\n", tmpKubeconfig)
		tmpNamespace := test.Namespace
		tmpNodeName, _ := tools.GetNodeName()
		tmpLabel := test.Label
		tmpPodName, err := tools.GetPodNameFromNodeAndLabel(tmpKubeconfig, tmpNamespace, tmpNodeName, tmpLabel)
		if err != nil {
			fmt.Printf("[DEV ERROR] Get test pod failed: %s\n", err)
			os.Exit(-1)
		}
		*podName = tmpPodName
		fmt.Printf("[DEV] Get test pod '%s'\n", *podName)
		// TODO: end of testing code
	}

	// do preflight check first
	checkedKubeconfig, nodeName, _, _, err := k8s.PreflightCheck(*kubeconfig)
	if err != nil {
		fmt.Printf("[ERROR] Preflight checking failed: %s\n", err)
		os.Exit(1)
	}

	sidecarProcesses, serviceProcesses, err := k8s.GetSidecarAndServiceProcess(checkedKubeconfig, nodeName, *namespace, *podName)
	if err != nil {
		fmt.Printf("[ERROR] Got err: %s\n", err)
		os.Exit(1)
	}
	fmt.Printf("[FINISHED] Get sidecar processes '%s'\n", sidecarProcesses)
	fmt.Printf("[FINISHED] Get service processes '%s'\n", serviceProcesses)

	var sidecarPid []int
	var servicePid []int
	var portList = []int{15006, 9080, 80, 8000}

	for i := 0; i < len(sidecarProcesses); i++ {
		sidecarPid = append(sidecarPid, int(sidecarProcesses[i].Pid))
	}
	for i := 0; i < len(serviceProcesses); i++ {
		servicePid = append(servicePid, int(serviceProcesses[i].Pid))
	}
	var pidList []int
	pidList = append(pidList, sidecarPid...)
	pidList = append(pidList, servicePid...)

	net.GetRequestOverSidecarEvent(sidecarPid, servicePid, portList, *podName)

	//targetPod, err := tools.LocateTargetPod(tools.GetDefaultKubeConfig(), *podName, *namespace)
	//so := net.SidecarOpt{
	//	SidecarPort: 8000,
	//	ServicePort: 80,
	//	LocalIP:     "127.0.0.1",
	//	PodIp:       targetPod.Status.PodIP,
	//	NodeIp:      targetPod.Status.HostIP,
	//}
	//
	//net.GetKernelNetworkEvent(pidList, so, *podName)
}
