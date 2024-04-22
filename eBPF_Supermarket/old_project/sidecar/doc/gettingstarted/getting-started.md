# Getting Started

To leverage the latest features of BPF, we recommend you to use Ubuntu 22.04.

## Install Kubernetes Environment

We recommend using a multi-node cluster for environment setup. But if you don't have the relevant conditions, you can also use minikube to build a single-node cluster.

### Kubernetes

You can use your own cluster, or use this document to set up:

https://kubernetes.io/docs/setup/production-environment/tools/kubeadm/create-cluster-kubeadm/

### Minikube

Minikube installation guide is as following.

https://minikube.sigs.k8s.io/docs/start/

On Ubuntu 22.04, you need to circumvent certain obstacles.

```shell
iptables -t filter -I FORWARD 1 -s 0.0.0.0/0 -d 0.0.0.0/0 -j ACCEPT
sysctl -w net.ipv4.ip_forward=1
systemctl stop firewalld
```

And then, start Minikube by those commands:

```shell
minikube start --kubernetes-version=v1.23.8 --mount-string='/home:/minikube-host' --base-image=kicbase/stable:v0.0.33
kubectl label nodes minikube sidecar-demo-node=dev
minikube mount /home:/minikube-host
```

If you want to experiment with the sidecar provided by this project, you need to connect to Minikube machine and do some preparations to build container images.

```shell
minikube ssh
cd /minikube-host
cd path/to/this/project
cd dev
make
```

## Set up Development Environment

### Install BCC:

```shell
sudo apt install -y bison build-essential cmake flex git libedit-dev \
libllvm14 llvm-14-dev libclang-14-dev python3 zlib1g-dev libelf-dev libfl-dev python3-distutils
git clone --depth 1 --branch v0.24.0 https://github.com/iovisor/bcc.git
mkdir bcc/build; cd bcc/build
cmake ..
make
sudo make install
cmake -DPYTHON_CMD=python3 .. # build python3 binding
pushd src/python/
make
sudo make install
popd
```

### Install Go

You can download and install Go quickly with the steps described [in the official documentation](https://go.dev/doc/install).

### Download All Go Dependencies

```shell
cd podstat
go mod tidy

# Verify the program
go build -v ./...
sudo go test ./...
```

## Start To Run

After all steps above, you can have a try of the program. The following examples are using project's developments pod described [here](../../dev). You can apply it or set up [Istio environment](https://istio.io/latest/docs/setup/getting-started/) by yourself.

### For Native Kubernetes

You can just specify the pod name, pod's namespace as arguments to start it.

```shell
sudo go run main.go --pod sidecar-demo
```

### For Minikube

When using minikube, you need to do some preparations as a notification to the program that minikube is used.

```shell
export MINIKUBE_ROOT_PID=$(docker inspect $(docker ps | grep minikube | awk -F ' ' '{print $1}') -f '{{.State.Pid}}')
export MINIKUBE_STARTED=TRUE
eval $(minikube -p minikube docker-env)
```

And then, just like a native Kubernetes cluster:

```shell
sudo go run main.go --pod sidecar-demo
```

In another terminal, you must start a new pod to send requests to the pod you are monitoring.

```shell
kubectl run tomcat --image tomcat
kubectl exec tomcat -- curl 172.17.0.2  # 172.17.0.2 is the IP of sidecar-demo pod
```

## Set up Visualization Components

See also: [Visualization Components Docs](../../visualization/components)
