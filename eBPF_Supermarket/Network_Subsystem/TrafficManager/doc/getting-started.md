# Getting Started

To leverage the latest features of BPF, we recommend you to use Ubuntu 22.04.

## Install Kubernetes Environment

We recommend using a multi-node cluster for environment setup. But if you don't have the relevant conditions, you can also use minikube to build a single-node cluster.

### Kubernetes

You can use your own cluster, or use this document to set up:

https://kubernetes.io/docs/setup/production-environment/tools/kubeadm/create-cluster-kubeadm/

### Minikube

Minikube's installation guide is as following.

https://minikube.sigs.k8s.io/docs/start/

On Ubuntu 22.04, you need to circumvent certain obstacles.

```shell
iptables -t filter -I FORWARD 1 -s 0.0.0.0/0 -d 0.0.0.0/0 -j ACCEPT
sysctl -w net.ipv4.ip_forward=1
systemctl stop firewalld
```

And then, start Minikube by those commands:

```shell
minikube start --kubernetes-version=1.26.6
```

## Set up Development Environment

To initialize development environment, please read the installation document [INSTALL.md](../INSTALL.md).

## Set up Visualization Components

During development, we used components for collecting metrics and visualization. You can install Prometheus and Grafana on master node.

```shell
touch prometheus.yml  # edit it!
docker run -d --name prometheus    -p 9090:9090 -v ~/data/prom-data:/prometheus -v $(pwd)/prometheus.yml:/etc/prometheus/prometheus.yml --user root prom/prometheus
docker run -d --name grafana	   -p 3000:3000	grafana/grafana
```

## Start To Run

We provide usage methods in different scenarios, including [Performance Test](../acceptance/performance_test.go), [Redirect Test](../acceptance/redirect_test.go), [Weighted Selection Test](../acceptance/weight_test.go), and [Automatic Monitoring Test](../acceptance/automatic/automatic_test.go). You can learn about development best practices by reading these implementations.

For redirection functions, we provide an example in [main.go](../main.go). Compile the program through `make build` command, and execute the redirection program by `./main --service sisyphe --namespace default`. Note that this program is only for testing and will exit immediately after 10 minutes. Please conduct secondary development according to your own scenarios.

Now you can test the redirection results in your cluster. We provide a siege container to perform stress testing within the cluster. If you have followed the previous steps, you should have a Pod named `siege`. Execute the following command:

```shell
kubectl exec siege -- siege -c 5 -r 20000 http://sisyphe.default.svc.cluster.local
```

You will get the following results. Try to adjust parameters to see the performance in different scenarios!

```json
{       
        "transactions":                       100000,
        "availability":                       100.00,
        "elapsed_time":                       107.31,
        "data_transferred":                     1.81,
        "response_time":                        0.01,
        "transaction_rate":                   931.88,
        "throughput":                           0.02,
        "concurrency":                          4.89,
        "successful_transactions":                 0,
        "failed_transactions":                     0,
        "longest_transaction":                  0.08,
        "shortest_transaction":                 0.00
}
```
