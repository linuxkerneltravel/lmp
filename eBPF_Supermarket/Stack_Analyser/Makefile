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
# author: luiyanbing@foxmail.com
#
# Makefile

OUTPUT := .output
BPF_SKEL := bpf_skel
CLANG ?= clang
CXX := clang
LIB := ../lib
LIBBPF_ROOT := $(abspath $(LIB)/libbpf)
LIBBPF_SRC := $(LIBBPF_ROOT)/src
BPFTOOL_SRC := $(abspath $(LIB)/bpftool/src)
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

VMLINUX := $(LIB)/vmlinux.h
# Use our own libbpf API headers and Linux UAPI headers distributed with
# libbpf to avoid dependency on system-wide headers, which could be missing or
# outdated
INCLUDES := -I./include -I./$(OUTPUT) -I./$(BPF_SKEL) -I$(LIBBPF_ROOT)/include/uapi -I$(dir $(VMLINUX))
CFLAGS := -Og -Wall
ALL_LDFLAGS := $(LDFLAGS) $(EXTRA_LDFLAGS)

BIN = $(patsubst src/%.cpp, %, ${wildcard src/*.cpp})
BPF = $(patsubst bpf/%.bpf.c, %, ${wildcard bpf/*.bpf.c})
BPF_OBJ = $(patsubst %,$(OUTPUT)/%.bpf.o,$(BPF))
BPF_SKEL_H = $(patsubst %,$(BPF_SKEL)/%.skel.h,$(BPF))
BPF_WAPPER = $(patsubst %,$(OUTPUT)/%.o,$(BPF))
BIN_OBJ = $(patsubst %,$(OUTPUT)/%.o,$(BIN))

TARGETS = stack_analyzer

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
args = `arg="$(filter-out $@,$(MAKECMDGOALS))" && echo $${arg:-${1}}`

.PHONY: all
all: $(TARGETS)

.PHONY: clean
clean:
	$(call msg,CLEAN)
	$(Q)rm -rf $(OUTPUT) $(TARGETS) $(BPF_SKEL)

init:
	$(call msg,INIT,$(LIB))
	$(Q)git submodule update --init --recursive ../lib/

$(LIBBPF_SRC) $(BPFTOOL_SRC): init

$(VMLINUX):
	$(call msg,BTFDUMP,$@)
	$(Q)bpftool btf dump file /sys/kernel/btf/vmlinux format c > $@

$(OUTPUT) $(OUTPUT)/libbpf $(BPFTOOL_OUTPUT) $(BPF_SKEL):
	$(call msg,MKDIR,$@)
	$(Q)mkdir -p $@

# Build libbpf
$(LIBBPF_OBJ): $(LIBBPF_SRC) $(wildcard $(LIBBPF_SRC)/*.[ch] $(LIBBPF_SRC)/Makefile) | $(OUTPUT)/libbpf
	$(call msg,LIB,$@)
	$(Q)$(MAKE) -C $(LIBBPF_SRC) BUILD_STATIC_ONLY=1  \
		    OBJDIR=$(dir $@)/libbpf DESTDIR=$(dir $@) \
		    INCLUDEDIR= LIBDIR= UAPIDIR=			  \
		    install

# Build bpftool
$(BPFTOOL): $(BPFTOOL_SRC) | $(BPFTOOL_OUTPUT)
	$(call msg,BPFTOOL,$@)
	$(Q)$(MAKE) ARCH= CROSS_COMPILE= OUTPUT=$(BPFTOOL_OUTPUT)/ -C $(BPFTOOL_SRC) bootstrap

# Build BPF code
$(BPF_OBJ): $(OUTPUT)/%.bpf.o: bpf/%.bpf.c include/ebpf.h $(LIBBPF_OBJ) $(VMLINUX) | $(OUTPUT) $(BPFTOOL)
	$(call msg,BPF,$@)
	$(Q)$(CLANG) -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH)		      \
		     $(INCLUDES) $(CLANG_BPF_SYS_INCLUDES)		      \
		     -c $(filter %.c,$^) -o $(patsubst %.bpf.o,%.tmp.bpf.o,$@)
	$(Q)$(BPFTOOL) gen object $@ $(patsubst %.bpf.o,%.tmp.bpf.o,$@)

# Generate BPF skeletons
$(BPF_SKEL_H): $(BPF_SKEL)/%.skel.h: $(OUTPUT)/%.bpf.o | $(OUTPUT) $(BPFTOOL) $(BPF_SKEL)
	$(call msg,GEN-SKEL,$@)
	$(Q)$(BPFTOOL) gen skeleton $< > $@

$(BPF_WAPPER): $(OUTPUT)/%.o: src/bpf_wapper/%.cpp include/bpf_wapper/%.h $(BPF_SKEL)/%.skel.h $(OUTPUT)/eBPFStackCollector.o
	$(call msg,CXX,$@)
	$(Q)$(CXX) $(CFLAGS) $(INCLUDES) -c $< -o $@

# Build depending library
$(BIN_OBJ): $(OUTPUT)/%.o: src/%.cpp $(BPF_SKEL_H)
	$(call msg,CXX,$@)
	$(Q)$(CXX) $(CFLAGS) $(INCLUDES) -c $< -o $@

$(OUTPUT)/eBPFStackCollector.o: src/bpf_wapper/eBPFStackCollector.cpp include/bpf_wapper/eBPFStackCollector.h | $(LIBBPF_OBJ)
	$(call msg,CXX,$@)
	$(Q)$(CXX) $(CFLAGS) $(INCLUDES) -c $< -o $@

# Build application binary
$(TARGETS): $(OUTPUT)/eBPFStackCollector.o $(BIN_OBJ) $(BPF_WAPPER) $(LIBBPF_OBJ)
	$(call msg,BINARY,$@)
	$(Q)$(CXX) $^ $(ALL_LDFLAGS) -lstdc++ -lelf -lz -o $@

# delete failed targets
.DELETE_ON_ERROR:

# keep intermediate (.skel.h, .bpf.o, etc) targets
.SECONDARY:
