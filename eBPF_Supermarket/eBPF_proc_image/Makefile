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

ARCH ?= $(shell uname -m | sed 's/x86_64/x86/' \
			 | sed 's/arm.*/arm/' \
			 | sed 's/aarch64/arm64/' \
			 | sed 's/ppc64le/powerpc/' \
			 | sed 's/mips.*/mips/' \
			 | sed 's/riscv64/riscv/' \
			 | sed 's/loongarch64/loongarch/')
APP = proc_image mutex_image

all: $(APP)

.PHONY: $(APP)
$(APP):
ifeq ($(wildcard ./vmlinux.h),)
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h
endif
	clang -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH) -I/usr/include/x86_64-linux-gnu -I. -c $@.bpf.c -o $@.bpf.o
	bpftool gen skeleton $@.bpf.o > $@.skel.h
	clang -g -O2 -Wall -I . -c $@.c -o $@.o
	clang -Wall -O2 -g $@.o -static -lbpf -lelf -lz -o $@

clean:
	rm -f *.o *.skel.h $(APP)