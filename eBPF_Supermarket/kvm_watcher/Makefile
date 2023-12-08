ARCH ?= $(shell uname -m | sed 's/x86_64/x86/' \
			 | sed 's/arm.*/arm/' \
			 | sed 's/aarch64/arm64/' \
			 | sed 's/ppc64le/powerpc/' \
			 | sed 's/mips.*/mips/' \
			 | sed 's/riscv64/riscv/' \
			 | sed 's/loongarch64/loongarch/')
APP = src/kvm_watcher

all: $(APP)

.PHONY: $(APP)
$(APP):
ifeq ($(wildcard ./include/vmlinux.h),)
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > ./include/vmlinux.h
endif
	clang -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH) -I/usr/include/x86_64-linux-gnu -I. -c $@.bpf.c -o $@.bpf.o
	bpftool gen skeleton $@.bpf.o > $@.skel.h
	clang -g -O2 -Wall -I . -c $@.c -o $@.o
	clang -Wall -O2 -g $@.o -static -lbpf -lelf -lz -o $(notdir $@)  

clean:
	cd src && rm -f *.o *.skel.h 
	sudo rm -rf $(notdir $(APP)) include/vmlinux.h temp