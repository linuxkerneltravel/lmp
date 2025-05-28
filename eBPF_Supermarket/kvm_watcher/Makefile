# Copyright 2023 The LMP Authors.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# https://github.com/linuxkerneltravel/lmp/blob/develop/LICENSE
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied. See the License for the specific language governing`
# permissions and limitations under the License.
#
# author: nanshuaibo811@163.com
#
# Compile scripts for kvm_watcher

OUTPUT := .output
CLANG ?= clang
LIBBPF_SRC := $(abspath ../lib/libbpf/src)
BPFTOOL_SRC := $(abspath ../lib/bpftool/src)
LIBBPF_OBJ := $(abspath $(OUTPUT)/libbpf.a)
BPFTOOL_OUTPUT ?= $(abspath $(OUTPUT)/bpftool)
BPFTOOL ?= $(BPFTOOL_OUTPUT)/bootstrap/bpftool
ARCH ?= $(shell uname -m | sed 's/x86_64/x86/' \
			 | sed 's/arm.*/arm/' \
			 | sed 's/aarch64/arm64/' \
			 | sed 's/ppc64le/powerpc/' \
			 | sed 's/mips.*/mips/' \
			 | sed 's/riscv64/riscv/' \
			 | sed 's/loongarch64/loongarch/')
# Use our own libbpf API headers and Linux UAPI headers distributed with
# libbpf to avoid dependency on system-wide headers, which could be missing or
# outdated
INCLUDES := -I$(OUTPUT) -I../lib/libbpf/include/uapi -Iinclude/  -Iinclude/bpf -Iinclude/commons
CFLAGS := -g -Wall
ALL_LDFLAGS := $(LDFLAGS) $(EXTRA_LDFLAGS)
SRC_DIR = src
COMMON_DIR = commons
APP = kvm_watcher
OPTIONS = -fm -w -n -d -e -h -c -i

# QEMU command line arguments variable
QEMU_CMD=sudo qemu-system-x86_64 -enable-kvm -cpu host -m 2048 -smp 4 -drive file=cirros-0.5.2-x86_64-disk.img,format=qcow2 -boot c -nographic

CIRROS_IMG_URL=https://gitee.com/nan-shuaibo/cirros/releases/download/0.5.2/cirros-0.5.2-x86_64-disk.img
CIRROS_IMG_FILE=cirros-0.5.2-x86_64-disk.img

# Define command to check for virtualization support
CHECK_VIRT_SUPPORT = [ $$(grep -Eoc '(vmx|svm)' /proc/cpuinfo) -eq 0 ]

# Define command to check if qemu-system-x86_64 process is running
CHECK_QEMU_RUNNING = pgrep -f qemu-system-x86_64 > /dev/null

CARGO ?= $(shell which cargo)

# Get Clang's default includes on this system. We'll explicitly add these dirs
# to the includes list when compiling with `-target bpf` because otherwise some
# architecture-specific dirs will be "missing" on some architectures/distros -
# headers such as asm/types.h, asm/byteorder.h, asm/socket.h, asm/sockios.h,
# sys/cdefs.h etc. might be missing.
#
# Use '-idirafter': Don't interfere with include mechanics except where the
# build would have failed anyways.
CLANG_BPF_SYS_INCLUDES ?= $(shell $(CLANG) -v -E - </dev/null 2>&1 \
	| sed -n '/<...> search starts here:/,/End of search list./{ s| \(/.*\)|-idirafter \1|p }')

ifeq ($(V),1)
	Q =
	msg =
else
	Q = @
	msg = @printf '  %-8s %s%s\n'					\
		      "$(1)"						\
		      "$(patsubst $(abspath $(OUTPUT))/%,%,$(2))"	\
		      "$(if $(3), $(3))";
	MAKEFLAGS += --no-print-directory
endif

COMMON_OBJ = \
	$(OUTPUT)/trace_helpers.o \
	$(OUTPUT)/uprobe_helpers.o \

define allow-override
  $(if $(or $(findstring environment,$(origin $(1))),\
            $(findstring command line,$(origin $(1)))),,\
    $(eval $(1) = $(2)))
endef

$(call allow-override,CC,$(CROSS_COMPILE)cc)
$(call allow-override,LD,$(CROSS_COMPILE)ld)

.PHONY: all
all: $(APP)

.PHONY: clean
clean:
	$(call msg,CLEAN)
	$(Q)rm -rf $(OUTPUT) $(APP)

$(OUTPUT) $(OUTPUT)/libbpf $(BPFTOOL_OUTPUT):
	$(call msg,MKDIR,$@)
	$(Q)mkdir -p $@

vmlinux: $(BPFTOOL)
	$(call msg,GEN-VMLINUX_H,$@)
	$(Q)$(BPFTOOL) btf dump file /sys/kernel/btf/kvm format c > ./include/vmlinux.h

.PHONY: deps
deps:
	$(call msg,INSTALL,$@)
	$(Q)sudo apt-get update && \
	 sudo apt-get install -y clang libelf-dev libpcap-dev gcc-multilib build-essential lolcat qemu-kvm wget

# Build libbpf
$(LIBBPF_OBJ): $(wildcard $(LIBBPF_SRC)/*.[ch] $(LIBBPF_SRC)/Makefile) | $(OUTPUT)/libbpf
	$(call msg,LIB,$@)
	$(Q)$(MAKE) -C $(LIBBPF_SRC) BUILD_STATIC_ONLY=1		      \
		    OBJDIR=$(dir $@)/libbpf DESTDIR=$(dir $@)		      \
		    INCLUDEDIR= LIBDIR= UAPIDIR=			      \
		    install

# Build bpftool
$(BPFTOOL): | $(BPFTOOL_OUTPUT)
	$(call msg,BPFTOOL,$@)
	$(Q)$(MAKE) ARCH= CROSS_COMPILE= OUTPUT=$(BPFTOOL_OUTPUT)/ -C $(BPFTOOL_SRC) bootstrap
	
# Build BPF code
$(OUTPUT)/%.bpf.o: $(SRC_DIR)/%.bpf.c $(LIBBPF_OBJ) $(wildcard %.h) vmlinux | $(OUTPUT) $(BPFTOOL)
	$(call msg,BPF,$@)
	$(Q)$(CLANG) -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH)		      \
		     $(INCLUDES) $(CLANG_BPF_SYS_INCLUDES)		      \
		     -c $(filter %.c,$^) -o $(patsubst %.bpf.o,%.tmp.bpf.o,$@)
	$(Q)$(BPFTOOL) gen object $@ $(patsubst %.bpf.o,%.tmp.bpf.o,$@)

# Generate BPF skeletons
$(OUTPUT)/%.skel.h: $(OUTPUT)/%.bpf.o | $(OUTPUT) $(BPFTOOL)
	$(call msg,GEN-SKEL,$@)
	$(Q)$(BPFTOOL) gen skeleton $< > $@


# Build user-space code
$(patsubst %,$(OUTPUT)/%.o,$(APP)):%.o: %.skel.h

$(OUTPUT)/%.o: $(SRC_DIR)/$(COMMON_DIR)/%.c $(wildcard %.h) $(LIBBPF_OBJ) | $(OUTPUT)
	$(call msg,CC,$@)
	$(Q)$(CC) $(CFLAGS) $(INCLUDES) -c $(filter %.c,$^) -o $@

$(OUTPUT)/%.o: $(SRC_DIR)/%.c $(wildcard %.h) | $(OUTPUT)
	$(call msg,CC,$@)
	$(Q)$(CC) $(CFLAGS) $(INCLUDES) -c $(filter %.c,$^) -o $@


# Build application binary
$(APP): %: $(OUTPUT)/%.o  $(LIBBPF_OBJ) $(COMMON_OBJ)  | $(OUTPUT)
	$(call msg,BINARY,$@)
	$(Q)$(CC) $(CFLAGS) $^ $(ALL_LDFLAGS) -lelf -lz -lzstd -o $@

test: $(APP)
	@if $(CHECK_VIRT_SUPPORT); then \
		echo "The CPU in your device does not support virtualization!"; \
		exit 1; \
	fi

	$(Q)#Load KVM modules
	$(Q)sudo modprobe kvm && sudo modprobe kvm-intel
	@if [ ! -f ./${CIRROS_IMG_FILE} ]; then \
		echo "Downloading CirrOS image $(CIRROS_IMG_FILE)..."; \
		$(Q)wget $(CIRROS_IMG_URL) -O $(CIRROS_IMG_FILE) || { echo "Download failed!" >&2; exit 1; }; \
	fi
	$(Q)# Start the virtual machine
	@if ! $(CHECK_QEMU_RUNNING); then \
		echo "\nQEMU not detected. Starting virtual machine..."; \
		$(QEMU_CMD) >/dev/null 2>&1 & \
		echo "Waiting for VM to boot (8 seconds)..."; \
		sleep 8; \
		if $(CHECK_QEMU_RUNNING); then \
		    echo "Virtual machine is now running."; \
		else \
		    echo "Failed to start virtual machine!" >&2; \
		    exit 1; \
		fi \
	else \
		echo "\nVirtual machine is already running..."; \
	fi
	$(Q)# Run kvm_watcher
	$(Q)echo "\nPreparing to run the $(notdir $(APP)) program..."
	$(Q)for opt in $(OPTIONS); do \
		echo "\nrunning $(notdir $(APP)) with option: $$opt"; \
		sleep 2; \
		sudo ./$(notdir $(APP)) $$opt -t 3; \
	done
	$(Q)# Terminate the QEMU virtual machine process
	$(Q)-sudo pkill -f "$(QEMU_CMD)"
	$(Q)echo "\nSuccessful test run of the $(notdir $(APP)) program."

# delete failed targets
.DELETE_ON_ERROR:

# keep intermediate (.skel.h, .bpf.o, etc) targets
.SECONDARY:
