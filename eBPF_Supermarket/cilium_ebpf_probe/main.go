package main

import (
	"cilium_ebpf_probe/cluster_utils"
	"cilium_ebpf_probe/http2_tracing"
	"cilium_ebpf_probe/http_kprobe"
	"context"
	"flag"
	"fmt"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/util/homedir"
	"path/filepath"
	//
	// Uncomment to load all auth plugins
	// _ "k8s.io/client-go/plugin/pkg/client/auth"
	//
	// Or uncomment to load specific auth plugins
	// _ "k8s.io/client-go/plugin/pkg/client/auth/azure"
	// _ "k8s.io/client-go/plugin/pkg/client/auth/gcp"
	// _ "k8s.io/client-go/plugin/pkg/client/auth/oidc"
	// _ "k8s.io/client-go/plugin/pkg/client/auth/openstack"
)

func main() {
	var kubeconfig *string
	//$KUBECONFIG=/etc/kubernetes/admin.conf
	if home := homedir.HomeDir(); home != "" {
		kubeconfig = flag.String("kubeconfig", filepath.Join("config"), "(optional) absolute path to the kubeconfig file")
	} else {
		kubeconfig = flag.String("kubeconfig", "/etc/kubernetes/admin.conf", "absolute path to the kubeconfig file")
	}
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

	// Examples for error handling:
	// - Use helper functions like e.g. errors.IsNotFound()
	// - And/or cast to StatusError and use its properties like e.g. ErrStatus.Message
	namespace := "wyw"
	/*******kprobe on pod************/
	pod := "httpserver"
	p, err := clientset.CoreV1().Pods(namespace).Get(context.TODO(), pod, metav1.GetOptions{})

	if errors.IsNotFound(err) {
		fmt.Printf("Pod %s in namespace %s not found\n", pod, namespace)
	} else if statusError, isStatus := err.(*errors.StatusError); isStatus {
		fmt.Printf("Error getting pod %s in namespace %s: %v\n",
			pod, namespace, statusError.ErrStatus.Message)
	} else if err != nil {
		panic(err.Error())
	} else {
		fmt.Printf("Found pod %s in namespace %s\n", pod, namespace)
		fmt.Printf("aaaa")
		res, _ := cluster_utils.GetAllPodProcess(clientset, "k8s-master", namespace, pod, p.Status.ContainerStatuses)
		for k, v := range res {
			fmt.Printf("get pod %s Pid and Attach Kprobe\n", k.Name)
			go http_kprobe.GetHttpViaKprobe(int(v[0].Pid), pod)
		}
	}

	/*******uprobe on pod************/
	poduprobe := "grpcserver"
	binaryPath := "/go/src/grpc_server/main"
	p2, err := clientset.CoreV1().Pods(namespace).Get(context.TODO(), poduprobe, metav1.GetOptions{})
	if errors.IsNotFound(err) {
		fmt.Printf("Pod %s in namespace %s not found\n", poduprobe, namespace)
	} else if statusError, isStatus := err.(*errors.StatusError); isStatus {
		fmt.Printf("Error getting pod %s in namespace %s: %v\n",
			poduprobe, namespace, statusError.ErrStatus.Message)
	} else if err != nil {
		panic(err.Error())
	} else {
		fmt.Printf("Found pod %s in namespace %s\n", poduprobe, namespace)
		res, _ := cluster_utils.GetPodELFPath(clientset, "k8s-master", namespace, poduprobe, p2.Status.ContainerStatuses)
		for k, v := range res {
			fmt.Printf("get pod %s Merge Path and Attach Uprobe\n", k.Name)
			fmt.Println(v)
			go http2_tracing.GetHttp2ViaUprobe(v+binaryPath, poduprobe)
		}
	}
	select {}
}
