ARCH ?= $(shell uname -m | sed 's/x86_64/x86/' \
			 | sed 's/arm.*/arm/' \
			 | sed 's/aarch64/arm64/' \
			 | sed 's/ppc64le/powerpc/' \
			 | sed 's/mips.*/mips/' \
			 | sed 's/riscv64/riscv/' \
			 | sed 's/loongarch64/loongarch/')
APP = src/ebpf_performance

# 编译器标志
CFLAGS=-g -O2 -Wall
BPF_CFLAGS=-g -O2 -target bpf

# 要链接的库
LIBS=-lbpf -lelf -lz -lzstd

# 默认目标
.PHONY: default
default: bpf

# 安装必要的依赖
.PHONY: deps
deps:
	sudo apt-get update && \
	sudo apt-get install -y clang libelf1 libelf-dev zlib1g-dev libbpf-dev \
		 linux-tools-$$(uname -r) linux-cloud-tools-$$(uname -r) \
		 libpcap-dev gcc-multilib build-essential lolcat 

# 头文件目录
INCLUDE_DIRS=-I/usr/include/x86_64-linux-gnu -I. -I./include -I./include/bpf -I./include/helpers
# 生成 vmlinux.h
.PHONY: vmlinux
vmlinux:
	bpftool btf dump file /sys/kernel/btf/kvm format c > ./include/vmlinux.h
	
# 编译BPF程序
$(APP).bpf.o: $(APP).bpf.c vmlinux
	clang $(BPF_CFLAGS) -D__TARGET_ARCH_$(ARCH) $(INCLUDE_DIRS) -c $< -o $@

# 生成BPF骨架文件
$(APP).skel.h: $(APP).bpf.o
	bpftool gen skeleton $< > $@

# 编译用户空间应用程序
${APP}.o: ${APP}.c
	clang $(CFLAGS) $(INCLUDE_DIRS) -c $< -o $@

# 链接用户空间应用程序与库
$(notdir $(APP)): ${APP}.o $(HELPERS_OBJ_FILES)
	clang -Wall $(CFLAGS) ${APP}.o $(HELPERS_OBJ_FILES) $(LIBS) -o $@
	@echo "BPF program compiled successfully."

# bpf 目标
.PHONY: bpf
bpf: $(APP).skel.h $(APP).bpf.o ${APP}.o $(HELPERS_OBJ_FILES) $(notdir $(APP))


clean:
	rm -f src/*.o src/*.skel.h src/helpers/*.o
	sudo rm -rf $(notdir $(APP)) include/vmlinux.h temp


