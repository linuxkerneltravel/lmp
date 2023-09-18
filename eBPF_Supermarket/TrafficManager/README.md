# Traffic Manager

[![Traffic Manager](https://github.com/linuxkerneltravel/lmp/actions/workflows/net_traffic_manager.yml/badge.svg)](https://github.com/linuxkerneltravel/lmp/actions/workflows/net_traffic_manager.yml)
[![LICENSE](https://img.shields.io/github/license/linuxkerneltravel/lmp.svg?style=square)](https://github.com/linuxkerneltravel/lmp/blob/develop/LICENSE)

## Introduction

Traffic Manager is an eBPF-based traffic management tool. It leverages **non-intrusive, high-speed kernel programmable mechanism** to achieve cost-effective and dynamic microservice traffic orchestration.

![Architecture](doc/img/architecture.svg)

## Capabilities

Based on abstractions of Kubernetes Services and Pods, as well as the modification of network request events, this project can achieve the following functionalities through refined operational logic:

**Service Resolution**: It directs request of Service directly to backend Pods, bypassing massive iptables lookups and iptables NAT.

**Non-intrusive Traffic Management**: It offers the ability to modify traffic across Pods and Services. Callers can invoke particular versions of a service, facilitating traffic migration or version rolling upgrades.

**Metric-Based Traffic Management:** By using metric inputs, it filters and eliminates abnormal Pods, preventing requests from reaching malfunctioning Pods. If all Pods are unable to work correctly, the request is denied outright (as shown in the diagram below).

![Dynamic Control](doc/img/dynamic-control.svg)

## Getting Started

For installation and initialization instructions, please refer to the documentation: [INSTALL.md](INSTALL.md).

To get started, check out the introductory guide [here](doc/getting-started.md).

## Documentation

Conceptual documentation is here to provide an understanding of overall architecture and implementation details: [CONCEPT.md](CONCEPT.md).

You can refer to some eBPF development documents at: [eBPF Development Tutorial](../sidecar/bpf/README.md#functional-bpf-programs).

## Roadmap

The roadmap provides an overview of the project's development plans and completion status. 

Detailed changelogs can be found here: [CHANGELOG.md](CHANGELOG.md).

- [x] Build the basic development framework and automatic compilation pipeline.
- [x] Implement kernel abstraction of Service and Pod, and design corresponding maps for storage and information transfer.
- [x] Implement cluster metadata analysis and map read and write update in user mode. Consider using the Kubernetes Controller's control loop to monitor changes to the current cluster and keep the metadata in the map always up to date.
- [x] Performance optimization and development framework arrangement.
- [x] Investigate and develop grayscale release function of traffic, such as canary release and blue-green release, which provides cross-Service traffic modification capabilities.
- [x] Implement filtering out specific abnormal nodes and Pods based on external cluster monitoring information.
- [x] Performance optimization.
- [x] Documentation and tutorials.
- [ ] Access more monitoring data sources, guide TrafficManager to conduct traffic management through more complex indicators, and even AI Ops mechanisms.
- [ ] Compress and reuse Map space, and minimize Map space through mechanisms such as `Union`.
- [ ] Dynamically update the Map mechanism instead of updating by deleting and re-inserting.
