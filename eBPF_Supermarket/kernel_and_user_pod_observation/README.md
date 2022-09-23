# Kernel and User Pod Observation

## Getting Started

```shell
go build -o kupod main.go
kubectl label nodes minikube sidecar-demo-node=dev
kubectl apply -f https://raw.githubusercontent.com/linuxkerneltravel/lmp/develop/eBPF_Supermarket/sidecar/dev/sidecar-demo.yaml
sudo ./kupod monitor all --pod sidecar-demo
```
