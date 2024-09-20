# SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
OUTPUT := .output
CLANG ?= clang
LIBBPF_SRC := $(abspath ../../lib/libbpf/src)
BPFTOOL_SRC := $(abspath ../../lib/bpftool/src)
LIBBPF_OBJ := $(abspath $(OUTPUT)/libbpf.a)
BPFTOOL_OUTPUT ?= $(abspath $(OUTPUT)/bpftool)
BPFTOOL ?= $(BPFTOOL_OUTPUT)/bootstrap/bpftool
VERSION_INFO := $(shell uname -r | cut -d'-' -f1)
VERSION_MAJOR := $(shell echo $(VERSION_INFO) | cut -d'.' -f1)
VERSION_MINOR := $(shell echo $(VERSION_INFO) | cut -d'.' -f2)
VERSION_PATCH := $(shell echo $(VERSION_INFO) | cut -d'.' -f3)
export VERSION_INFO
export VERSION_MAJOR
export VERSION_MINOR
export VERSION_PATCH
ARCH ?= $(shell uname -m | sed 's/x86_64/x86/' \
			 | sed 's/arm.*/arm/' \
			 | sed 's/aarch64/arm64/' \
			 | sed 's/ppc64le/powerpc/' \
			 | sed 's/mips.*/mips/' \
			 | sed 's/riscv64/riscv/' \
			 | sed 's/loongarch64/loongarch/')
LOGSRC := ./data/doc
VMDIR := ../../lib/vmlinux
VMLINUXSRC := $(VMDIR)/$(ARCH)
VMLINUX := $(VMLINUXSRC)/vmlinux.h
# Use our own libbpf API headers and Linux UAPI headers distributed with
# libbpf to avoid dependency on system-wide headers, which could be missing or
# outdated
INCLUDES := -I$(OUTPUT) -I ../../lib/libbpf/include/uapi -I$(dir $(VMLINUX))
CFLAGS := -g -Wall
ALL_LDFLAGS := $(LDFLAGS) $(EXTRA_LDFLAGS)

APPS = netwatcher

# Get Clang's default includes on this system. We'll explicitly add these dirs
# to the includes list when compiling with `-target bpf` because otherwise some
# architecture-specific dirs will be "missing" on some architectures/distros -
# headers such as asm/types.h, asm/byteorder.h, asm/socket.h, asm/sockios.h,
# sys/cdefs.h etc. might be missing.
#
# Use '-idirafter': Don't interfere with include mechanics except where the
# build would have failed anyways.
CLANG_BPF_SYS_INCLUDES = $(shell $(CLANG) -v -E - </dev/null 2>&1 \
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
all: deps $(APPS)
#更新vmlinux.h文件
.PHONY: deps
deps:check_bpftool check_clang check_multilib
	@echo "Kernel version is $(VERSION_MAJOR).$(VERSION_MINOR).$(VERSION_PATCH)"
	mkdir -p $(VMLINUXSRC)
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > $(VMLINUX)

.PHONY: check_bpftool
check_bpftool:
	@if ! command -v bpftool &> /dev/null; then \
		echo "bpftool 未安装，正在安装..."; \
		sudo apt-get update; \
		sudo apt-get install -y linux-tools-$(shell uname -r); \
	else \
		echo "bpftool 已经安装"; \
	fi
.PHONY: check_clang

check_clang:
	@if ! command -v clang &> /dev/null; then \
		echo "clang 未安装，正在安装..."; \
		sudo apt-get update; \
		sudo apt-get install -y clang; \
	else \
		echo "clang 已经安装"; \
	fi

# 检查 multilib 是否安装，如果没有则安装
.PHONY: check_multilib
check_multilib:
	@if [ ! -f /usr/include/x86_64-linux-gnu/gnu/stubs-32.h ]; then \
		echo "multilib 未安装，正在安装..."; \
		sudo apt-get update; \
		sudo apt-get install -y gcc-multilib g++-multilib; \
	else \
		echo "multilib 已经安装"; \
	fi

.PHONY: clean
clean:
	$(call msg,CLEAN)
	$(Q)rm -rf $(OUTPUT) $(APPS)
	
	rm -rf $(LOGSRC)
	rm -rf $(VMDIR)
	
.PHONY: clean2
clean2:
	$(call msg,CLEAN)
	rm -f $(APPS)
	rm -f $(OUTPUT)/*.skel.h
	rm -f $(OUTPUT)/*.o
	rm -rf $(LOGSRC)
	rm -rf $(VMDIR)
	
$(OUTPUT) $(OUTPUT)/libbpf $(BPFTOOL_OUTPUT):
	$(call msg,MKDIR,$@)
	$(Q)mkdir -p $@

# Build libbpf
$(LIBBPF_OBJ): $(wildcard $(LIBBPF_SRC)/*.[ch] $(LIBBPF_SRC)/Makefile) | $(OUTPUT)/libbpf
	$(call msg,LIB,$@)
	$(Q)$(MAKE) -C $(LIBBPF_SRC) BUILD_STATIC_ONLY=1		      \
		    OBJDIR=$(dir $@)libbpf DESTDIR=$(dir $@)		      \
		    INCLUDEDIR= LIBDIR= UAPIDIR=			      \
		    install

# Build bpftool
$(BPFTOOL): | $(BPFTOOL_OUTPUT)
	$(call msg,BPFTOOL,$@)
	$(Q)$(MAKE) ARCH= CROSS_COMPILE= OUTPUT=$(BPFTOOL_OUTPUT)/ -C $(BPFTOOL_SRC) bootstrap

# Build BPF code
$(OUTPUT)/%.bpf.o: %.bpf.c $(LIBBPF_OBJ) $(wildcard *.h) $(VMLINUX) | $(OUTPUT) $(BPFTOOL)
	$(call msg,BPF,$@)
	$(Q)$(CLANG) -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH)		      \
			 -D__TARGET_ARCH_$(ARCH) \
		     -DVERSION_MAJOR=$(VERSION_MAJOR) \
		     -DVERSION_MINOR=$(VERSION_MINOR) \
		     -DVERSION_PATCH=$(VERSION_PATCH) \
		     $(INCLUDES) $(CLANG_BPF_SYS_INCLUDES)		      \
		     -c $(filter %.c,$^) -o $(patsubst %.bpf.o,%.tmp.bpf.o,$@)
	$(Q)$(BPFTOOL) gen object $@ $(patsubst %.bpf.o,%.tmp.bpf.o,$@)

# Generate BPF skeletons
$(OUTPUT)/%.skel.h: $(OUTPUT)/%.bpf.o | $(OUTPUT) $(BPFTOOL)
	$(call msg,GEN-SKEL,$@)
	$(Q)$(BPFTOOL) gen skeleton $< > $@

# Build user-space code
$(patsubst %,$(OUTPUT)/%.o,$(APPS)): %.o: %.skel.h

$(OUTPUT)/%.o: %.c $(wildcard %.h) | $(OUTPUT) $(wildcard %.h)
	$(call msg,CC,$@)
	$(Q)$(CC) $(CFLAGS) $(INCLUDES) -c $(filter %.c,$^) -o $@

# Build application binary
$(APPS): %: $(OUTPUT)/%.o $(LIBBPF_OBJ) | $(OUTPUT)
	$(call msg,BINARY,$@)
	$(Q)$(CC) $(CFLAGS) $^ $(ALL_LDFLAGS) -lelf -lz -o $@

# delete failed targets
.DELETE_ON_ERROR:

# keep intermediate (.skel.h, .bpf.o, etc) targets
.SECONDARY:

SHELL := /bin/bash
test:
	sleep 1.5s && curl -s www.baidu.com -o /dev/null &
	sudo timeout -s SIGINT 3 ./netwatcher -a || if [[ $$? != 124 && $$? != 0 ]];then exit $$?;fi
	cat $(shell pwd)/data/connects.log
	sleep 1.5s && curl -s www.baidu.com -o /dev/null &
	sudo timeout -s SIGINT 3 ./netwatcher -ax || if [[ $$? != 124 && $$? != 0 ]];then exit $$?;fi
	cat $(shell pwd)/data/connects.log
	sleep 1.5s && curl -s www.baidu.com -o /dev/null &
	sudo timeout -s SIGINT 3 ./netwatcher -axr || if [[ $$? != 124 && $$? != 0 ]];then exit $$?;fi
	cat $(shell pwd)/data/connects.log
	sleep 1.5s && curl -s www.baidu.com -o /dev/null &
	sudo timeout -s SIGINT 3 ./netwatcher -t || if [[ $$? != 124 && $$? != 0 ]];then exit $$?;fi
	sleep 1.5s && curl -s www.baidu.com -o /dev/null &
	sudo timeout -s SIGINT 3 ./netwatcher -ti || if [[ $$? != 124 && $$? != 0 ]];then exit $$?;fi