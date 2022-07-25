# Development Environment Setup

This directory is about development environment setup, for quick setup for development environment and demo presentation.

There are three subdirectories, they are:
 - [init](init): to build an init image for Kubernetes pod network configuration
 - [sidecar](sidecar): to build a sidecar image to provide a proxy for service pod
 - [service](service): to build a service image to provide a webserver service

## Usage

```shell
kubectl create namespace sidecar
kubectl label nodes YOUR_NODE_NAME sidecar-demo-node=dev
make all
kubectl apply -f sidecar-demo.yaml -n sidecar
kubectl get pods -o wide -n sidecar
```

![pod-info](sidecar-demo-pod-info.png)
