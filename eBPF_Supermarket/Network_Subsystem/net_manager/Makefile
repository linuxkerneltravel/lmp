# SPDX-License-Identifier: (GPL-2.0 OR BSD-2-Clause)

# Compiler and Tools
LLC ?= llc
CLANG ?= clang
CC ?= gcc

# Targets
XDP_TARGETS  := netmanager_kern
USER_TARGETS := netmanager

XDP_C = ${XDP_TARGETS:=.c}
XDP_OBJ = ${XDP_C:.c=.o}
USER_C := ${USER_TARGETS:=.c}
USER_OBJ := ${USER_C:.c=.o}

# Directories
COMMON_DIR = ./common
LIB_DIR ?= ./lib
LOADER_DIR ?= $(LIB_DIR)/xdp-tools/xdp-loader
STATS_DIR ?= $(COMMON_DIR)/../basic-solutions

# Common Objects and Dependencies
COMMON_OBJS += $(COMMON_DIR)/common_user_bpf_xdp.o $(COMMON_DIR)/common_params.o
EXTRA_DEPS := $(COMMON_DIR)/parsing_helpers.h
COMMON_H := ${COMMON_OBJS:.o=.h}

include $(LIB_DIR)/defines.mk
KERN_USER_H ?= $(wildcard common_kern_user.h)
COMMON_MK = $(COMMON_DIR)/common.mk

# Extra Linker/Compiler Flags
CFLAGS += -I$(LIB_DIR)/install/include $(EXTRA_CFLAGS) -g 
BPF_CFLAGS += -I$(LIB_DIR)/install/include $(EXTRA_CFLAGS) -g
LDFLAGS += -L$(LIB_DIR)/install/lib

# Verbosity Control
ifeq ("$(origin V)", "command line")
	VERBOSE = $(V)
endif
ifndef VERBOSE
	VERBOSE = 0
endif

ifeq ($(VERBOSE),0)
	MAKEFLAGS += --no-print-directory -s
	Q = @
endif

# Projects and Cleaning
PROJ := xacl_ip router xacl_mac xstate
PROJ_CLEAN = $(addsuffix _clean,$(PROJ))

.PHONY: clean clobber distclean $(PROJ) $(PROJ_CLEAN) $(CLANG) $(LLC)

# Default Target
# all: lib $(PROJ) net_manager 
all: lib $(PROJ) netmanager_kern.o netmanager_kern.skel.h net_manager

# Clean Target
clean: $(PROJ_CLEAN)
	@echo; echo common; $(MAKE) -C common clean
	@echo; echo lib; $(MAKE) -C lib clean
	$(Q)rm -f $(USER_TARGETS) $(XDP_OBJ) $(USER_OBJ) $(COPY_LOADER) $(COPY_STATS) *.ll $(XLB_OBJS) netmanager_kern.skel.h
	
# Build Library
lib: config.mk check_submodule
	@echo; echo $@; $(MAKE) -C $@

# Project Build Targets
$(PROJ):
	@echo; echo $@; $(MAKE) -C $@

# Main Target
net_manager: llvm-check $(USER_TARGETS) $(XDP_OBJ) $(COPY_LOADER) $(COPY_STATS)

netmanager_kern.skel.h: netmanager_kern.o
	sudo bpftool gen skeleton netmanager_kern.o > netmanager_kern.skel.h

# Copy Loader
ifdef COPY_LOADER
$(LOADER_DIR)/$(COPY_LOADER):
	$(Q)make -C $(LOADER_DIR)

$(COPY_LOADER): $(LOADER_DIR)/$(COPY_LOADER)
	$(QUIET_COPY)cp $(LOADER_DIR)/$(COPY_LOADER) $(COPY_LOADER)
endif

# Copy Stats
ifdef COPY_STATS
$(STATS_DIR)/$(COPY_STATS):	$(STATS_DIR)/${COPY_STATS:=.c} $(COMMON_H)
	$(Q)make -C $(STATS_DIR) $(COPY_STATS)

$(COPY_STATS):	$(STATS_DIR)/$(COPY_STATS)
	$(QUIET_COPY)cp $(STATS_DIR)/$(COPY_STATS) $(COPY_STATS)
EXTRA_DEPS += $(COMMON_DIR)/xdp_stats_kern.h $(COMMON_DIR)/xdp_stats_kern_user.h
endif

# LLVM Tool Check
llvm-check: $(CLANG) $(LLC)
	@for TOOL in $^ ; do \
		if [ ! $$(command -v $${TOOL} 2>/dev/null) ]; then \
			echo "*** ERROR: Cannot find tool $${TOOL}" ;\
			exit 1; \
		else true; fi; \
	done

$(OBJECT_LIBBPF):
	@if [ ! -d $(LIBBPF_DIR) ]; then \
		echo "Error: Need libbpf submodule" $(LIBBPF_DIR); \
		echo "May need to run git submodule update --init"; \
		exit 1; \
	else \
		cd $(LIBBPF_DIR) && $(MAKE) all OBJDIR=.; \
		mkdir -p build; $(MAKE) install_headers DESTDIR=build OBJDIR=.; \
	fi

$(OBJECT_LIBXDP):
	@if [ ! -d $(LIBXDP_DIR) ]; then \
		echo "Error: Need libxdp submodule" $(LIBXDP_DIR); \
		echo "May need to run git submodule update --init"; \
		exit 1; \
	else \
		cd $(LIBXDP_DIR) && $(MAKE) all OBJDIR=.; \
	fi

# Create dependency: detect if C-file change and touch H-file, to trigger
# target $(COMMON_OBJS)
$(COMMON_H): %.h: %.c
	touch $@

# Detect if any of common obj changed and create dependency on .h-files
$(COMMON_OBJS):	%.o: %.h
	$(Q)$(MAKE) -C $(COMMON_DIR)

# $(USER_TARGETS): %: %.c  $(OBJECT_LIBBPF) $(OBJECT_LIBXDP) Makefile $(COMMON_MK) $(COMMON_OBJS) $(KERN_USER_H) $(EXTRA_DEPS) $(XLB_OBJS)
# 	$(QUIET_CC)$(CC) -Wall $(CFLAGS) $(LDFLAGS) -o $@ $(COMMON_OBJS) $(XLB_OBJS) $(LIB_OBJS) \
# 	 $< $(LDLIBS)
$(USER_TARGETS): %: %.c netmanager_kern.skel.h $(OBJECT_LIBBPF) $(OBJECT_LIBXDP) Makefile $(COMMON_MK) $(COMMON_OBJS) $(KERN_USER_H) $(EXTRA_DEPS) $(XLB_OBJS)
	$(QUIET_CC)$(CC) -Wall $(CFLAGS) $(LDFLAGS) -o $@ $(COMMON_OBJS) $(XLB_OBJS) $(LIB_OBJS) \
	$< $(LDLIBS)

$(XDP_OBJ): %.o: %.c  Makefile $(COMMON_MK) $(KERN_USER_H) $(EXTRA_DEPS) $(OBJECT_LIBBPF)
	$(QUIET_CLANG)$(CLANG) -S \
	    -target bpf \
	    -D __BPF_TRACING__ \
	    $(BPF_CFLAGS) \
	    -Wall \
	    -Wno-unused-value \
	    -Wno-pointer-sign \
	    -Wno-compare-distinct-pointer-types \
	    -Werror \
	    -O2 -emit-llvm -c -g -o ${@:.o=.ll} $<
	$(QUIET_LLC)$(LLC) -march=bpf -filetype=obj -o $@ ${@:.o=.ll}


$(PROJ_CLEAN):
	@echo; echo $@; $(MAKE) -C $(subst _clean,,$@) clean

config.mk: configure
	@sh configure

clobber:
	@touch config.mk
	$(Q)$(MAKE) clean
	$(Q)rm -f config.mk

distclean:	clobber

check_submodule:
	@if [ -d .git ] && `git submodule status lib/libbpf | grep -q '^+'`; then \
		echo "" ;\
		echo "** WARNING **: git submodule SHA-1 out-of-sync" ;\
		echo " consider running: git submodule update"  ;\
		echo "" ;\
	fi\
