.DEFAULT_GOAL := all

all: build
	sudo ./main

build:
	cd bpf; go generate;
	go build -o main main.go

init:
	cd bpf/headers/bpf/; ./update.sh
	cd bpf/headers/; bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

trace:
	sudo cat /sys/kernel/debug/tracing/trace_pipe

clean:
	rm main

test:
	pwd
	env
	sudo mkdir /root/.kube
	sudo cp ~/.kube/config /root/.kube/config
	kubectl get nodes
	kubectl get pods -owide -A
	kubectl get services
	sleep 120
#	test_pod() {
#		while [[ $(kubectl get pods -l $1 -o 'jsonpath={..status.conditions[?(@.type=="Ready")].status}') != "True True True True True True True True True True True True True True True True True True True True True True True True True" ]]
#		do
#			echo "waiting for pod"
#			sleep 5
#			kubectl get pods -o wide -A;
#		done
#		return 0
#	}
#	test_pod app=sisyphe
	# test_pod app=sisyphe-sfs
	# sudo go test -v ./...

	kubectl get nodes
	kubectl get pods -owide -A
	kubectl get services
	sudo make build
	sudo go test -v ./...
