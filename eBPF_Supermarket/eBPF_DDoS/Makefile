.PHONY: builder xdp_dns test threshold clean-test

all: builder xdp_dns

builder:
	docker build -t bpf-builder:latest .

xdp_dns:
	docker run --rm -ti -v$(shell pwd):/input -v$(shell pwd)/build:/output \
       	bpf-builder sh -c "cd /input/src && make DEBUG=$(DEBUG)"

test:
	docker run -d -m 128m --expose=53 --expose=53/udp -p 53:53 -p 53:53/udp \
	-v $(shell pwd)/test/config:/etc/coredns --name dwq-coredns burkeazbill/docker-coredns -conf /etc/coredns/Corefile
	docker run --privileged -d --name dwq-ddos-test --network=container:dwq-coredns \
	-v /lib/modules:/lib/modules -v /usr/src:/usr/src -v /sys/kernel/debug:/sys/kernel/debug \
	-v /sys/fs/bpf:/sys/fs/bpf -v $(shell pwd):/ddos bpf-builder \
	sh -c "cd /ddos/src && make xdp_dns_kern && \
	ip link set dev eth0 xdp obj xdp_dns_kern.o sec xdp && \
	python3 catch_dns.py"

threshold:
	docker exec dwq-ddos-test sh -c "bpftool map update pinned /sys/fs/bpf/xdp/globals/fail_counter key 0 0 0 0 value $(value) 0 0 0"

interval:
	docker exec dwq-ddos-test sh -c "bpftool map update pinned /sys/fs/bpf/xdp/globals/fail_counter key 255 255 255 255 value $(value) 0 0 0"

clean-test:
	docker rm -f dwq-ddos-test
	docker rm -f dwq-coredns
	rm -rf /sys/fs/bpf/xdp/globals/fail_counter
