.SILENT:
ARCH ?= $(shell uname -m | sed 's/x86_64/x86/' \
			 | sed 's/arm.*/arm/' \
			 | sed 's/aarch64/arm64/' \
			 | sed 's/ppc64le/powerpc/' \
			 | sed 's/mips.*/mips/' \
			 | sed 's/riscv64/riscv/' \
			 | sed 's/loongarch64/loongarch/')
APP = src/kvm_watcher

OPTIONS = -f -w -n -d -e

# 共同规则1
define common_rules1
	# 安装依赖
	sudo apt install clang libelf1 libelf-dev zlib1g-dev libbpf-dev linux-tools-$$(uname -r) linux-cloud-tools-$$(uname -r)
	# 生成vmlinux.h文件
	bpftool btf dump file /sys/kernel/btf/kvm format c > ./include/vmlinux.h
endef

# 共同规则2
define common_rules2
	# 编译ebpf程序
	clang -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH) -I/usr/include/x86_64-linux-gnu -I. -c $@.bpf.c -o $@.bpf.o
	bpftool gen skeleton $@.bpf.o > $@.skel.h
	clang -g -O2 -Wall -I . -c $@.c -o $@.o
	clang -Wall -O2 -g $@.o -static -lbpf -lelf -lz -lzstd -o $(notdir $@) # 6.5内核编译需要lzstd库
endef

# 判断是否已安装 qemu-system-x86_64
ifeq (,$(shell which qemu-system-x86_64))
	INSTALL_QEMU = sudo apt update && sudo apt install qemu-kvm
endif

bpf: $(APP) 
test: $(APP)


.PHONY: $(APP)
$(APP):
# 如果参数为test：
ifeq ($(MAKECMDGOALS),test)
ifeq ($(shell grep -Eoc '(vmx|svm)' /proc/cpuinfo),0)
	$(error "The CPU in your device does not support virtualization!")
endif
	# 加载KVM模块
	sudo modprobe kvm && sudo modprobe kvm-intel
	$(common_rules1)
	$(common_rules2)
ifeq ($(wildcard ./cirros-0.5.2-x86_64-disk.img),)
	wget https://gitee.com/nan-shuaibo/cirros/releases/download/0.5.2/cirros-0.5.2-x86_64-disk.img
endif
	# 安装 qemu
	$(INSTALL_QEMU)
	# 启动虚拟机
    ifneq ($(shell pgrep -f qemu-system-x86_64),)
		echo "\nVirtual machine is running..."
		sleep 1
    else
		echo "\nWaiting for the virtual machine to start..."
		sudo qemu-system-x86_64 -enable-kvm -cpu host -m 2048 -smp 4 -drive file=cirros-0.5.2-x86_64-disk.img,format=qcow2 -boot c -nographic >/dev/null 2>&1 &
		sleep 8
		echo "\nVirtual machine is running..."
		sleep 1
    endif
	# 运行kvm_watcher
	echo "\nPreparing to run the kvm_watcher program..."
	for opt in $(OPTIONS); do \
        echo "\nrunning kvm_watcher with option: $$opt"; \
		sleep 2 ;\
		sudo ./kvm_watcher $$opt -t 3; \
    done
	# 结束qemu虚拟机进程
	-sudo pkill -f "qemu-system-x86_64 -enable-kvm -cpu host -m 2048 -smp 4 -drive file=cirros-0.5.2-x86_64-disk.img,format=qcow2 -boot c -nographic"
	echo "\nSuccessful test run of the kvm_watcher program."
# 如果参数为空或者为bpf
else
ifeq ($(wildcard ./include/vmlinux.h),)
	$(common_rules1)
endif
	$(common_rules2)
	echo "\nCompilation successful!"
endif

clean:
	cd src && rm -f *.o *.skel.h 
	sudo rm -rf $(notdir $(APP)) include/vmlinux.h temp*


