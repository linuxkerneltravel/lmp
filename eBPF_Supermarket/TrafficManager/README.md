# eBPF Traffic Manager

Based on the abstraction of Kubernetes Service and Pod, and the modification of network request events, this project can realize the following functions:

1. Parse Service and redirect requests directly to backend Pods, avoiding the NAT of iptables.
2. Filter out abnormal Pods to avoid requesting Pods that cannot work normally. If none of the pods are working, reject the request.
3. Grayscale release: canary release and blue-green release. Provides cross-Service traffic modification capabilities. Select a specific part of the caller to call a specific version of the service to realize traffic migration or version upgrade.
4. Support consistent hashing: use relevant fields (such as IP, port, protocol, etc.) for hash mapping to ensure that multiple requests from a specific source will be directed to a unique backend Pod.

## Install tutorial

### Ubuntu 22.04

```bash
# Install Go
wget https://go.dev/dl/go1.20.5.linux-amd64.tar.gz
rm -rf /usr/local/go && tar -C /usr/local -xzf go1.20.5.linux-amd64.tar.gz
export PATH=$PATH:/usr/local/go/bin

# Install Docker
sudo snap refresh
sudo snap install docker

# Install and start local Kubernetes
sudo snap install kubectl --classic
curl -LO https://storage.googleapis.com/minikube/releases/latest/minikube-linux-amd64
sudo install minikube-linux-amd64 /usr/local/bin/minikube
sudo minikube start --kubernetes-version=1.26.6 --force

# Install eBPF development tools
sudo apt install -y llvm clang
sudo apt install libbfd-dev libcap-dev libelf-dev
git clone --recurse-submodules https://github.com/libbpf/bpftool.git
sudo make install -C bpftool/src/
sudo cp bpftool/src/bpftool /usr/bin/
sudo rm -rf bpftool/
```

```bash
sudo make init
sudo make
```

## Usage

Developing...

## Roadmap

Project development plan:

- [x] Build the basic development framework and automatic compilation pipeline.
- [x] Implement kernel abstraction of Service and Pod, and design corresponding maps for storage and information transfer.
- [ ] Implement cluster metadata analysis and map read and write update in user mode. Consider using the Kubernetes Controller's control loop to monitor changes to the current cluster and keep the metadata in the map always up to date.
- [ ] Performance optimization and development framework arrangement.
- [ ] Investigate and develop consistent hashing capabilities to achieve fast hashing and fast Pod selection.
- [ ] Investigate and develop grayscale release function of traffic, such as canary release and blue-green release, which provides cross-Service traffic modification capabilities.
- [ ] Implement filtering out specific abnormal nodes and Pods based on external cluster monitoring information.
- [ ] Documentation and tutorials.
