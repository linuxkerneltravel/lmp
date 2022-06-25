package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/eswzy/podstat/k8s"
	"github.com/eswzy/podstat/tools"
)

func main() {
	kubeconfig := flag.String("kubeconfig", "", "path to the kubeconfig file")
	podName := flag.String("pod", "productpage-v1-bla-bla", "name of the pod to inspect")
	namespace := flag.String("namespace", "default", "namespace for this pod")
	flag.Parse()

	{
		// TODO: testing code, delete it after the test
		// https://istio.io/latest/docs/setup/getting-started/
		tmpKubeconfig := "/etc/kubernetes/admin.conf"
		tmpNamespace := "default"
		tmpNodeName, _ := tools.GetNodeName()
		tmpLabel := "app=ratings,version=v1"
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

	sidecarProcessBPF, serviceProcessBPF, err := k8s.GetSidecarAndServiceProcess(checkedKubeconfig, nodeName, *namespace, *podName)
	fmt.Printf("[FINISHED] Get sidecar process '%s'\n", sidecarProcessBPF)
	fmt.Printf("[FINISHED] Get service process '%s'\n", serviceProcessBPF)

	//processMap, err := k8s.GetAllPodProcess(checkedKubeconfig, nodeName, *namespace, *podName)
	//if err != nil {
	//	fmt.Println(err)
	//	os.Exit(1)
	//}
	//
	//for containerStatues, processes := range processMap {
	//	_ = containerStatues
	//	fmt.Println("[INFO]====================================")
	//	fmt.Println("[INFO] PID \tPPID \tCOMM \tCMD")
	//	for _, resProcess := range processes {
	//		ppid, _ := resProcess.Ppid()
	//		name, _ := resProcess.Name()
	//		cmdline, _ := resProcess.Cmdline()
	//		fmt.Println("[INFO]", resProcess.Pid, "\t", ppid, "\t", name, "\t", cmdline)
	//	}
	//	fmt.Println("[INFO]====================================")
	//}
}
