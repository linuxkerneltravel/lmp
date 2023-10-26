# Install tutorial

## Ubuntu 22.04

### Install Dependencies

```bash
# Install Go
wget https://go.dev/dl/go1.20.5.linux-amd64.tar.gz
rm -rf /usr/local/go && tar -C /usr/local -xzf go1.20.5.linux-amd64.tar.gz
export PATH=$PATH:/usr/local/go/bin

# Install Docker
snap refresh
snap install docker

# Install and start local Kubernetes
snap install kubectl --classic
curl -LO https://storage.googleapis.com/minikube/releases/latest/minikube-linux-amd64
sudo install minikube-linux-amd64 /usr/local/bin/minikube
minikube start --kubernetes-version=1.26.6 --force

# Install eBPF development tools
apt update -y
apt install -y llvm clang make gcc
apt install -y libbfd-dev libcap-dev libelf-dev
git clone --recurse-submodules https://github.com/libbpf/bpftool.git
make install -C bpftool/src/
cp bpftool/src/bpftool /usr/bin/
rm -rf bpftool/
```

### Apply Test Data

```bash
kubectl apply -f acceptance/testdata/k8s/
```

### Initialization

```bash
make init
make
```
