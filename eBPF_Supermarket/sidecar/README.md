# Performance Monitoring and Optimization Analysis of Sidecar

<!--![LOGO here](doc/logo/logo.png)-->

## Introduction

PMOAS is a eBPF-based tool for comprehensive monitoring and visualization of pods with sidecar, which provides efficient and powerful monitoring and visualization tools. It includes network event capture, flow of data packets in the pod's internal network protocol stack, container resource consumption acquisition in pod and so on, with visualization on the industry's common used visualization platforms.

## Background

In the cloud native scenario, in order to facilitate traffic governance of microservices, the service discovery, load balance, rate limiting, service routing and other service governance functions related to network traffic are often encapsulated into sidecar for implementation. The sidecar is always deployed near the microservices to take over the upstream and downstream network request traffic of microservices applications. 

Although the intrusion into the business code can be greatly reduced through the sidecar mode, the introduction of a new component for traffic management will inevitably cause performance losses. Especially, in the case of extremely high RPS, the performance of sidecar will even become an important bottleneck to limit microservices.

Therefore, monitoring the resource consumption and network delay related to the sidecar can provide sufficient data support in terms of business code organization, network structure optimization, and reasonable resource scheduling, and verify whether the optimization effect is manifested.

## Functionality Overview

### Easy way to get Kubernetes resources

Due to the need of a lot of k8s data, this project encapsulates a large number of relevant information extraction steps, from top-level pod status information to container information to bottom-level process information.

### Flexible sidecar differentiation strategy

At the beginning of the design, this project focused on the flexible classification of sidecars, which can support both common sidecars and customized sidecars.

### TCP accept and connect between sidecar and service probe

As a proxy commonly used in the microservice field, sidecars often handle many short connections. Therefore, a large number of accept and connect events will be generated in those pods. Thus, with the powerful observability of eBPF, this project first uses network request events [accept(2)](https://man7.org/linux/man-pages/man2/accept.2.html) and [connetc(2)](https://man7.org/linux/man-pages/man2/connect.2.html) as the basic analysis dimension to monitor the occurrence and statistical indicators of network requests.

### Panoramic view of network protocol stack analysis

In some high-concurrency scenarios, based on the optimization of kernel mode and user mode, sidecar request connections to business containers may be merged. This will cause many network events to be skipped. In order to avoid this obstacle to observability and improve the monitoring of the status of the pod's internal network, this project uses eBPF to analyze the entire network protocol stack, and displays it in a pipelined way, so that the analyst can clearly recognize the current flow of network packets.

### Data transmission acceleration based on socket redirecting

This is a network forwarding feature based on the unique function of eBPF, which can realize direct communication between sockets, thereby allowing data to bypass the entire network protocol stack. This method can [greatly speed up the transmission of network packets](./doc/demo/sockops.md) between the sidecar and the business container, and also supports the forwarding of ALL LOCAL SOCKETS! Accelerate together!

### Metrics collection, storage and visualization

Monitoring of performance is an important part of this project. Then the display of monitoring results is also an indispensable part. To achieve this, we use Prometheus and Grafana stacks, which is common used, open system, and also easy to integrate with existing systems.

## Getting Started

- [Why This Project?](#introduction)
- [Getting Started](./doc/gettingstarted/getting-started.md)
- [Architecture and Concepts](./doc/overviews/component-overview.md)
- [Visualization Component Installing](./visualization/components/README.md)
- [Development Guide of BPF](./bpf/README.md)

## Roadmap

This is the development roadmap for the project. If you are interested in this project, you can get involved through the following features.

- Monitor
  - Refine the network events in the network protocol stack, and count the interval time of any event of interest
  - Calculate and export richer network statistical indicators and visualize them
- Optimization
  - Replace NAT inside a pod via BPF programs
  - Based on the above functions, manage the behavior of traffic passing through sidecar to adapt to some extreme cases
- Architecture
  - Package and encapsulate the project as a DaemonSet for automated deployment on Kubernetes platform
  - Optimize command line management
