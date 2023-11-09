ARCH ?= $(shell uname -m | sed 's/x86_64/x86/' \
			 | sed 's/arm.*/arm/' \
			 | sed 's/aarch64/arm64/' \
			 | sed 's/ppc64le/powerpc/' \
			 | sed 's/mips.*/mips/' \
			 | sed 's/riscv64/riscv/' \
			 | sed 's/loongarch64/loongarch/')
APP = cs_delay

VMLINUX := ../../vmlinux/$(ARCH)/vmlinux.h
all:
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h
	clang -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH) -I/usr/include/x86_64-linux-gnu -I. -c $(APP).bpf.c -o $(APP).bpf.o
	bpftool gen skeleton $(APP).bpf.o > $(APP).skel.h
	clang -g -O2 -Wall -I . -c $(APP).c -o $(APP).o
	clang -Wall -O2 -g $(APP).o -static -lbpf -lelf -lz -o $(APP)


other:
	clang -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH) -I/usr/include/x86_64-linux-gnu -I. -c $(APP).bpf.c -o $(APP).bpf.o
	bpftool gen skeleton $(APP).bpf.o > $(APP).skel.h
	clang -g -O2 -Wall -I . -c $(APP).c -o $(APP).o
	clang -Wall -O2 -g $(APP).o -static -lbpf -lelf -lz -o $(APP)

clean:
	rm *.o *.skel.h  $(APP) vmlinux.h