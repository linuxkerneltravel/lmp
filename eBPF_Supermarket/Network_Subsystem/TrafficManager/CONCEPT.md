# Concept

In microservice system, during peak traffic periods, the entire microservice cluster experiences high load. Especially when the load surpasses the cluster's maximum capacity, it can lead to excessive load on specific nodes, rendering them unable to process subsequent requests.

Furthermore, in a microservice system, there are cascading dependencies between service instances. If downstream service instance nodes fail, it can cause upstream service instances to enter a waiting or crashing state. Therefore, there is a need to proactively reject potentially failing requests to achieve quick failure.

Currently, the process of fast request failure requires invasive methods like implementing sidecars or using iptables. However, these methods often suffer from performance and operability issues. Hence, there is a need to efficiently determine and redirect request traffic using Linux kernel's eBPF technology, ensuring that traffic is always directed towards available service instances.

As a result, this project leverages eBPF technology in combination with microservice techniques to establish a non-intrusive mechanism for determining and redirecting microservice request traffic. Key capabilities include replacing a large number of iptables lookups and NATs for service requests, supporting fast weighted backend pod selection techniques (instead of random selection), facilitating kernel-level microservice canary testing, and dynamically adjusting the weight assigned to backend pod selection based on external performance metrics (enabling dynamic traffic allocation based on performance metric changes).

## Overall Architecture

The following is the overall architecture of the project:

![Architecture](doc/img/architecture.svg)

TrafficManager will collect data from multiple sources, including cluster metadata information from Kubernetes, availability and performance data from metric monitoring systems or AI Ops systems. After comprehensive analysis, it will distribute Pod handling and selection logic into kernel-mode Control Map and Data Map. Kernel-mode monitoring and operations begin after attaching the eBPF program.

When Pods within the cluster initiate requests to specific services (e.g., `http://<svc>.<ns>.svc.cluster.local`), the eBPF program attached by TrafficManager intercepts the execution of connect(2) system call. After identifying, analyzing, rendering a verdict, and performing redirection, it completes user-transparent modifications of request, allowing redirection to a new target Pod. At this point, the request will smoothly traverse the overlay network and directly reach the target Pod on the target node (`http://<pod>.<svc>.<ns>.svc.cluster.local`).

## Design and Implementation

### Abstraction and Storage Design

For eBPF, when we need to pass user-space data to kernel-space, we must utilize eBPF Map. However, eBPF Maps are mostly key-value pairs, which are not conducive to storing the complex information of Pods, Services, and other entities in their original form. Therefore, it is essential to consider the abstraction of these fields and their mapping relationships. As a result, we have divided this part into two maps based on their functions: Data Map and Control Map.

#### Data Map

The Data Map is solely used to store metadata for backend Pods and is indexed using unique identifiers. It serves as data storage.

![Data Map](doc/img/data-map.svg)

#### Control Map

The Control Map is used to swiftly analyze the current cluster's operational status and select an appropriate result to modify the current request based on pre-defined action rules when a request is detected. In its design, it uses target IP, target port, and an index number for lookups.

When the index number is 0, it is typically used to analyze the current service's status and necessitates a secondary lookup to select a backend Pod. Different behaviors correspond to different formats of the "Options" field to achieve several functionalities within this project.

![Control Map](doc/img/control-map.svg)

### Traffic Control Methods

Based on the introduction above, we can discern the defined data structures. Here is an explanation of how these data structures are utilized. Please note that these usage methods may be changed or expanded as development progresses.

![Traffic Control](doc/img/traffic-control.svg)

For the standard backend selection method based on random lookup, we set the index number to 0 and perform a combined lookup in the Control Map using the target IP and port of the current request. This allows us to determine the number of backend Pods of this Service. For example, for Service 1, as illustrated above, there are two backend Pods. Selection is then done based on a 50% distribution, using a random Pod index as the index number for the lookup. After obtaining the Backend ID, we can look up the destination Pod's IP and port in Data Map.

For the weight-based selection method (as seen in the above diagram for Service 2 - old), the initial steps are the same as random lookup selection, but there is an additional field indicating the selection probability (i.e., weight) of the current Pod. The eBPF program employs an O(log_2(n)) complexity algorithm to choose a suitable backend Pod.

For services marked for traffic canary (as seen in the above diagram for Service 2 - new), there are additional fields to control the selection of the older version service. The selection process for other Pods is similar to the weight-based selection method. However, if the older version service is chosen as the destination for traffic based on weight, we retrieve relevant information for the older version service from Data Map and perform backend Pod selection through a **separate** lookup process (as shown in the diagram for Service 2 - old).

### Dynamic Traffic Management

With this project, we can achieve dynamic traffic management to address various cluster states. The diagram below outlines a dynamic traffic management approach based on load metrics (refer to [automatic_test.go](../acceptance/automatic/automatic_test.go)).

![Dynamic Traffic](doc/img/dynamic-control.svg)

After obtaining load metrics through monitoring tools like Node Exporter, cAdvisor, etc., the data is stored in Prometheus. These metrics will be used to assess the availability of the cluster, nodes, and individual Pods. The assessment can be based on traditional metric calculations or incorporate AI Ops techniques for more sophisticated evaluations.

Once the availability of the cluster, nodes, and individual Pods has been calculated, TrafficManager will perform comprehensive assessments and design corresponding strategies for the service. These strategies may include traffic handling methods, identification of non-functioning Pods, and traffic allocation proportions for each Pod.

Finally, this information is distributed to the kernel space through the associated maps and eBPF programs for request handling.
