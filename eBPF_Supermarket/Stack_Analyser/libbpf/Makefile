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

ORIG_ARCH ?= $(shell uname -m)
ARCH ?= $(shell echo $(ORIG_ARCH) | sed 's/x86_64/x86/' \
			 | sed 's/arm.*/arm/' \
			 | sed 's/aarch64/arm64/' \
			 | sed 's/ppc64le/powerpc/' \
			 | sed 's/mips.*/mips/' \
			 | sed 's/riscv64/riscv/' \
			 | sed 's/loongarch64/loongarch/')
APP = stack_analyzer
bpf = on_cpu_count off_cpu_count mem_count

all: vmlinux.h $(bpf) symbol
	clang -g -O2 -Wall -I. -I./include -c $(APP).cc -o $(APP).o
	clang -Wall -O2 -g $(APP).o symbol.o elf.o -static -lbpf -lelf -lz -lstdc++ -o $(APP)

vmlinux.h:
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

$(bpf): %: bpf/%.bpf.c
	clang -Wunknown-attributes -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH) -I/usr/include/$(ORIG_ARCH)-linux-gnu -I. -I./include -c bpf/$@.bpf.c -o bpf/$@.bpf.o
	bpftool gen skeleton bpf/$@.bpf.o > bpf/$@.skel.h

symbol: %: include/%.cc
	clang -g -O2 -Wall -c include/symbol.cc -o symbol.o
	clang -g -O2 -Wall -c include/elf.cc -o elf.o

clean:
	rm bpf/*.o bpf/*.skel.h *.o $(APP) vmlinux.h