# SPDX-License-Identifier: (GPL-2.0 OR BSD-2-Clause)

XDP_TARGETS  := xdp_prog_kern
USER_TARGETS := xdp_loader
USER_TARGETS += xdp_stats
USER_TARGETS += xacladm

COMMON_DIR = ../common

# Extend with another COMMON_OBJS
COMMON_OBJS += $(COMMON_DIR)/common_user_bpf_xdp.o

XLB_OBJS += map_common.o

EXTRA_DEPS := $(COMMON_DIR)/parsing_helpers.h

include $(COMMON_DIR)/common.mk
