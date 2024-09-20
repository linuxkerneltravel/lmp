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
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# author: zhangziheng0525@163.com
#
# compile the current folder code

# SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
OUTPUT := .output
CLANG ?= clang
LIBBPF_SRC := $(abspath ../libbpf/src)
BPFTOOL_SRC := $(abspath ../bpftool/src)
LIBBPF_OBJ := $(abspath $(OUTPUT)/libbpf.a)
BPFTOOL_OUTPUT ?= $(abspath $(OUTPUT)/bpftool)
BPFTOOL ?= $(BPFTOOL_OUTPUT)/bootstrap/bpftool
LIBBLAZESYM_SRC := $(abspath ../blazesym/)
LIBBLAZESYM_INC := $(abspath $(LIBBLAZESYM_SRC)/include)
LIBBLAZESYM_OBJ := $(abspath $(OUTPUT)/libblazesym.a)
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
INCLUDES := -I$(OUTPUT) -I../libbpf/include/uapi -I$(LIBBLAZESYM_INC) -I./include
CFLAGS := -g -Wall
ALL_LDFLAGS := $(LDFLAGS) $(EXTRA_LDFLAGS)

APPS = resource_image lock_image syscall_image keytime_image schedule_image mfutex
WORKTOOL := proc_image
CONTROLLER := controller

SRC_DIR = ./include
COMMON_OBJ = \
	$(OUTPUT)/hashmap.o \
	$(OUTPUT)/trace_helpers.o \
	$(OUTPUT)/uprobe_helpers.o \

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

define allow-override
  $(if $(or $(findstring environment,$(origin $(1))),\
            $(findstring command line,$(origin $(1)))),,\
    $(eval $(1) = $(2)))
endef

$(call allow-override,CC,$(CROSS_COMPILE)cc)
$(call allow-override,LD,$(CROSS_COMPILE)ld)

.PHONY: all
all: $(CONTROLLER) $(WORKTOOL) SUCCESS_MESSAGE

.PHONY: clean
clean:
	$(call msg,CLEAN)
	$(Q)rm -rf $(OUTPUT) $(WORKTOOL) $(CONTROLLER)

$(OUTPUT) $(OUTPUT)/libbpf $(BPFTOOL_OUTPUT):
	$(call msg,MKDIR,$@)
	$(Q)mkdir -p $@

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
$(OUTPUT)/%.bpf.o: bpf/%.bpf.c $(LIBBPF_OBJ) $(wildcard %.h) $(VMLINUX) | $(OUTPUT) $(BPFTOOL)
	$(call msg,BPF,$@)
	$(Q)$(CLANG) -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH)		      \
		     $(INCLUDES) $(CLANG_BPF_SYS_INCLUDES)		      \
		     -c $(filter %.c,$^) -o $(patsubst %.bpf.o,%.tmp.bpf.o,$@)
	$(Q)$(BPFTOOL) gen object $@ $(patsubst %.bpf.o,%.tmp.bpf.o,$@)

# Generate BPF skeletons
.PHONY: $(APPS)
$(APPS): %: $(OUTPUT)/%.bpf.o | $(OUTPUT) $(BPFTOOL)
	$(call msg,GEN-SKEL,$@)
	$(Q)$(BPFTOOL) gen skeleton $< > $(OUTPUT)/$@.skel.h

# Build user-space code
$(OUTPUT)/%.o: $(SRC_DIR)/%.c | $(OUTPUT)
	$(call msg,CC,$@)
	$(Q)$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

$(OUTPUT)/%.o: $(CONTROLLER).c | $(OUTPUT)
	$(call msg,CC,$@)
	$(Q)$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

$(OUTPUT)/$(WORKTOOL).o: $(WORKTOOL).c $(APPS) | $(OUTPUT)
	$(call msg,CC,$@)
	$(Q)$(CC) $(CFLAGS) $(INCLUDES) -c $(filter %.c,$^) -o $@

# Build application binary and Create a file for storing data
$(CONTROLLER): %: $(OUTPUT)/%.o $(COMMON_OBJ) $(LIBBPF_OBJ) | $(OUTPUT)
	$(call msg,BINARY,$@)
	$(Q)$(CC) $^ $(ALL_LDFLAGS) -lstdc++ -lelf -lz -o $@

$(WORKTOOL): %: $(OUTPUT)/%.o $(COMMON_OBJ) $(LIBBPF_OBJ) | $(OUTPUT)
	$(call msg,BINARY,$@)
	$(Q)$(CC) $^ $(ALL_LDFLAGS) -lstdc++ -lelf -lz -o $@
	@mkdir -p $(OUTPUT)/data
	@[ -f $(OUTPUT)/data/offcpu_stack.txt ] || touch $(OUTPUT)/data/offcpu_stack.txt

SUCCESS_MESSAGE:
	@echo "        ____  ____  ______   ____                     ____                         "
	@echo "  ___  / __ )/ __ \/ ____/  / __ \_________  _____   /  _/___ ___  ____ _____ ____ "
	@echo " / _ \/ __  / /_/ / /_     / /_/ / ___/ __ \/ ___/   / // __ \`__ \/ __ \`/ __ \`/ _ \\"
	@echo "/  __/ /_/ / ____/ __/    / ____/ /  / /_/ / /__   _/ // / / / / / /_/ / /_/ /  __/"
	@echo "\___/_____/_/   /_/      /_/   /_/   \____/\___/  /___/_/ /_/ /_/\__,_/\__, /\___/ "
	@echo "                                                                      /____/        "
	@echo "Successful to compile eBPF_proc_image tools:"
	@echo "proc_image ——— Pre-attach to eBPF program, data is collected and output after activation"
	@echo "controller ——— Controller for proc_image tool"
	@echo "Please start your use ~"

# delete failed targets
.DELETE_ON_ERROR:

# keep intermediate (.skel.h, .bpf.o, etc) targets
.SECONDARY: