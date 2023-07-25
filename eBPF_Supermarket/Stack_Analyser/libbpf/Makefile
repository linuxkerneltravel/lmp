ORIG_ARCH ?= $(shell uname -m)
ARCH ?= $(shell echo $(ORIG_ARCH) | sed 's/x86_64/x86/' \
			 | sed 's/arm.*/arm/' \
			 | sed 's/aarch64/arm64/' \
			 | sed 's/ppc64le/powerpc/' \
			 | sed 's/mips.*/mips/' \
			 | sed 's/riscv64/riscv/' \
			 | sed 's/loongarch64/loongarch/')
APP = stack_analyzer
bpf = on_cpu_count off_cpu_count

all: vmlinux $(bpf) 
	clang -g -O2 -Wall -I . -c $(APP).c -o $(APP).o
	clang -Wall -O2 -g $(APP).o -static -lbpf -lelf -lz -o $(APP)

vmlinux:
ifeq ($(wildcard ./vmlinux.h),)
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h
endif

$(bpf): %: bpf/%.bpf.c
	clang -Wunknown-attributes -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH) -I/usr/include/x86_64-linux-gnu -I. -c bpf/$@.bpf.c -o bpf/$@.bpf.o
	bpftool gen skeleton bpf/$@.bpf.o > bpf/$@.skel.h

clean:
	rm bpf/*.o bpf/*.skel.h *.o $(APP) vmlinux.h