package main

import (
	"context"
	"flag"
	"fmt"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
	"lmp/eBPF_Supermarket/cilium_ebpf_probe/cluster_utils"
	"lmp/eBPF_Supermarket/cilium_ebpf_probe/http2_tracing"
	"lmp/eBPF_Supermarket/cilium_ebpf_probe/http_kprobe"
)

var (
	kubeconfig *string
	pod        *string
	poduprobe  *string
	imagename  *string
	imagename2 *string
	namespace  *string
	nodename   *string
	prometheus *string
)

func main() {
	//$KUBECONFIG=/etc/kubernetes/admin.conf
	kubeconfig = flag.String("kubeconfig", "/etc/kubernetes/admin.conf", "absolute path to the kubeconfig file")

	pod = flag.String("pod", "httpserver", "pod name of http protocol")
	poduprobe = flag.String("poduprobe", "grpcserver", "pod name of http2 protocol")

	imagename = flag.String("image1", "wyuei/http_server:v2.0", "docker image of http protocol")
	imagename2 = flag.String("image2", "wyuei/grpc_server:latest", "docker image of http2 protocl")

	namespace = flag.String("namespace", "wyw", "namespace of your pod")

	nodename = flag.String("nodename", "k8s-node2", "node which your pods running on")
	prometheus = flag.String("prometheus", "10.10.103.122:9091", "where your prometheus running on")
	flag.Parse()

	// use the current context in kubeconfig
	config, err := clientcmd.BuildConfigFromFlags("", *kubeconfig)
	//通过参数（master的url或者kubeconfig路径）和BuildConfigFromFlags方法来获取rest.Config对象，
	if err != nil {
		panic(err.Error())
	}

	// create the clientset
	clientset, err := kubernetes.NewForConfig(config)
	//通过*rest.Config参数和NewForConfig方法来获取clientset对象，clientset是多个client的集合，每个client可能包含不同版本的方法调用
	if err != nil {
		panic(err.Error())
	}

	pods, err := clientset.CoreV1().Pods("wyw").List(context.TODO(), metav1.ListOptions{})
	if err != nil {
		panic(err.Error())
	}
	fmt.Printf("There are %d pods in the cluster in wyw namespace\n", len(pods.Items))

	/*******kprobe on pod************/
	p, err := clientset.CoreV1().Pods(*namespace).Get(context.TODO(), *pod, metav1.GetOptions{})
	if errors.IsNotFound(err) {
		fmt.Printf("Pod %s in namespace %s not found\n", *pod, *namespace)
	} else if statusError, isStatus := err.(*errors.StatusError); isStatus {
		fmt.Printf("Error getting pod %s in namespace %s: %v\n",
			*pod, *namespace, statusError.ErrStatus.Message)
	} else if err != nil {
		panic(err.Error())
	} else {
		fmt.Printf("Found pod %s in namespace %s\n", *pod, *namespace)
		res, _ := cluster_utils.GetAllPodProcess(clientset, *nodename, *namespace, *pod, p.Status.ContainerStatuses, *imagename)
		for k, v := range res {
			fmt.Printf("get pod %s Pid and Attach Kprobe\n", k.Name)
			go http_kprobe.GetHttpViaKprobe(int(v[0].Pid), *pod, *prometheus)
		}
	}

	/*******uprobe on pod************/
	binaryPath := "/go/src/grpc_server/main"
	p2, err := clientset.CoreV1().Pods(*namespace).Get(context.TODO(), *poduprobe, metav1.GetOptions{})
	if errors.IsNotFound(err) {
		fmt.Printf("Pod %s in namespace %s not found\n", *poduprobe, *namespace)
	} else if statusError, isStatus := err.(*errors.StatusError); isStatus {
		fmt.Printf("Error getting pod %s in namespace %s: %v\n",
			*poduprobe, *namespace, statusError.ErrStatus.Message)
	} else if err != nil {
		panic(err.Error())
	} else {
		fmt.Printf("Found pod %s in namespace %s\n", *poduprobe, *namespace)
		res, _ := cluster_utils.GetPodELFPath(clientset, *nodename, *namespace, *poduprobe, p2.Status.ContainerStatuses, *imagename2)
		for k, v := range res {
			fmt.Printf("get pod %s Merge Path and Attach Uprobe\n", k.Name)
			go http2_tracing.GetHttp2ViaUprobe(v+binaryPath, *poduprobe, *prometheus)
		}
	}
	select {}
}
