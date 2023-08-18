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
