ARCH ?= $(shell uname -m | sed 's/x86_64/x86/' \
			 | sed 's/arm.*/arm/' \
			 | sed 's/aarch64/arm64/' \
			 | sed 's/ppc64le/powerpc/' \
			 | sed 's/mips.*/mips/' \
			 | sed 's/riscv64/riscv/' \
			 | sed 's/loongarch64/loongarch/')
APP = src/kvm_watcher

OPTIONS = -fm -w -n -d -e -h -c -i

# 编译器标志
CFLAGS=-g -O2 -Wall
BPF_CFLAGS=-g -O2 -target bpf

# 要链接的库
LIBS=-lbpf -lelf -lz -lzstd

# 头文件目录
INCLUDE_DIRS=-I/usr/include/x86_64-linux-gnu -I. -I./include -I./include/bpf -I./include/helpers

# 帮助函数
HELPERS_OBJ_DIR := src/helpers
HELPERS_FILES := $(wildcard $(HELPERS_OBJ_DIR)/*.c)
HELPERS_OBJ_FILES := $(patsubst $(HELPERS_OBJ_DIR)/%.c,$(HELPERS_OBJ_DIR)/%.o,$(HELPERS_FILES))

# 默认目标
.PHONY: default
default: bpf

# 安装必要的依赖
.PHONY: deps
deps:
	sudo apt-get update && \
	sudo apt-get install -y clang libelf1 libelf-dev zlib1g-dev libbpf-dev \
		 linux-tools-$$(uname -r) linux-cloud-tools-$$(uname -r) \
		 libpcap-dev gcc-multilib build-essential lolcat qemu-kvm wget

# 生成 vmlinux.h
.PHONY: vmlinux
vmlinux:
	bpftool btf dump file /sys/kernel/btf/kvm format c > ./include/vmlinux.h

# 编译helpers目录下的所有.c文件
$(HELPERS_OBJ_DIR)/%.o: $(HELPERS_OBJ_DIR)/%.c
	clang $(CFLAGS) $(INCLUDE_DIRS) -c $< -o $@

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


# qemu 命令行参数变量化
QEMU_CMD=sudo qemu-system-x86_64 -enable-kvm -cpu host -m 2048 -smp 4 -drive file=cirros-0.5.2-x86_64-disk.img,format=qcow2 -boot c -nographic

CIRROS_IMG_URL=https://gitee.com/nan-shuaibo/cirros/releases/download/0.5.2/cirros-0.5.2-x86_64-disk.img
CIRROS_IMG_FILE=cirros-0.5.2-x86_64-disk.img

# 定义检查虚拟化支持的命令
CHECK_VIRT_SUPPORT = [ $$(grep -Eoc '(vmx|svm)' /proc/cpuinfo) -eq 0 ]

# 定义检查 qemu-system-x86_64 进程是否存在的命令
CHECK_QEMU_RUNNING = [ "$$(pgrep -f qemu-system-x86_64)" ]

.PHONY: test
test: bpf
	@if $(CHECK_VIRT_SUPPORT); then \
		echo "The CPU in your device does not support virtualization!"; \
		exit 1; \
	fi
	# 加载KVM模块
	sudo modprobe kvm && sudo modprobe kvm-intel
	@if [ ! -f ./${CIRROS_IMG_FILE} ]; then \
		wget $(CIRROS_IMG_URL) -O $(CIRROS_IMG_FILE); \
	fi
	# 启动虚拟机
	@if $(CHECK_QEMU_RUNNING); then \
		echo "\nWaiting for the virtual machine to start..."; \
		$(QEMU_CMD) >/dev/null 2>&1 & \
		sleep 8; \
		echo "\nVirtual machine is running..."; \
	else \
		echo "\nVirtual machine is already running..."; \
	fi
	# 运行kvm_watcher
	echo "\nPreparing to run the $(notdir $(APP)) program..."; \
	for opt in $(OPTIONS); do \
		echo "\nrunning $(notdir $(APP)) with option: $$opt"; \
		sleep 2; \
		sudo ./$(notdir $(APP)) $$opt -t 3; \
	done
	# 结束qemu虚拟机进程
	-sudo pkill -f "$(QEMU_CMD)"
	echo "\nSuccessful test run of the $(notdir $(APP)) program."



clean:
	rm -f src/*.o src/*.skel.h src/helpers/*.o
	sudo rm -rf $(notdir $(APP)) include/vmlinux.h temp


