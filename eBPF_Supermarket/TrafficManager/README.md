# eBPF Traffic Manager

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
