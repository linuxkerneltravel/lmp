# Init Container

Init containers are used as a prior step before 

Istio uses an init container to set up the Pod networking in order to set up the necessary iptables rules.

In this container, to make sure sidecar container will intercept requests between user and service container, we should set iptables rules like:

```shell
# Forward TCP traffic on port 80 to port 8000 on the eth0 interface.
iptables -t nat -A PREROUTING -p tcp -i eth0 --dport 80 -j REDIRECT --to-port 8000

# List all iptables rules.
iptables -t nat --list
```
