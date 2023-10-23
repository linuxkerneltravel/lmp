.PHONY: builder xdp_dns test clean-test

all: builder xdp_dns

builder:
	docker build -t bpf-builder:latest .

xdp_dns:
	docker run --rm -ti -v$(shell pwd):/input -v$(shell pwd)/build:/output \
       	bpf-builder sh -c "cd /input/src && make DEBUG=$(DEBUG)"

test-dns-server:
	docker run -d -m 128m --expose=53 --expose=53/udp -p 53:53 -p 53:53/udp \
	-v $(shell pwd)/test/config:/etc/coredns --name dwq-coredns burkeazbill/docker-coredns -conf /etc/coredns/Corefile

test: test-dns-server
	docker run --privileged -d --name dwq-ddos-test --network=container:dwq-coredns \
	-v /lib/modules:/lib/modules -v /usr/src:/usr/src -v /sys/kernel/debug:/sys/kernel/debug:rw \
	-v /sys/fs/bpf:/sys/fs/bpf -v $(shell pwd):/ddos bpf-builder \
	sh -c "mount -t bpf bpf /sys/fs/bpf && cd /ddos/src && make xdp_dns_kern && \
	ip link set dev eth0 xdpgeneric obj xdp_dns_kern.o sec xdp && \
	python3 -u catch_dns.py"

fail-threshold:
	docker exec dwq-ddos-test sh -c "bpftool map update pinned /sys/fs/bpf/xdp/globals/configuration key 0 value $(value) 0 0 0"

count-threshold:
	docker exec dwq-ddos-test sh -c "bpftool map update pinned /sys/fs/bpf/xdp/globals/configuration key 1 value $(value) 0 0 0"

any-threshold:
	docker exec dwq-ddos-test sh -c "bpftool map update pinned /sys/fs/bpf/xdp/globals/configuration key 2 value $(value) 0 0 0"

global-any-threshold:
	docker exec dwq-ddos-test sh -c "bpftool map update pinned /sys/fs/bpf/xdp/globals/configuration key 3 value $(value) 0 0 0"

global-fail-threshold:
	docker exec dwq-ddos-test sh -c "bpftool map update pinned /sys/fs/bpf/xdp/globals/configuration key 4 value $(value) 0 0 0"

interval:
	docker exec dwq-ddos-test sh -c "bpftool map update pinned /sys/fs/bpf/xdp/globals/configuration key 200 value $(value) 0 0 0"

enforce-tcp:
	docker exec dwq-ddos-test sh -c "bpftool map update pinned /sys/fs/bpf/xdp/globals/configuration key 201 value 1 0 0 0"

remove-enforce-tcp:
	docker exec dwq-ddos-test sh -c "bpftool map delete pinned /sys/fs/bpf/xdp/globals/configuration key 201"

logs:
	docker logs dwq-ddos-test

dump:
	docker exec dwq-ddos-test sh -c "echo configuration: && bpftool map dump pinned /sys/fs/bpf/xdp/globals/configuration && echo counter: && bpftool map dump pinned /sys/fs/bpf/xdp/globals/counter"

clean-test:
	docker rm -f dwq-ddos-test
	docker rm -f dwq-coredns
	rm -rf /sys/fs/bpf/xdp/globals/counter
	rm -rf /sys/fs/bpf/xdp/globals/configuration
