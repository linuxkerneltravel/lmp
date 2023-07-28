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

obj-m += mutex_test1.o

CURRENT_PATH:=$(shell pwd)	#模块所在的当前所在路径
LINUX_KERNEL:=$(shell uname -r)	#linux内核代码的当前版本
LINUX_KERNEL_PATH:=/usr/src/linux-headers-$(LINUX_KERNEL)	#linux内核的当前版本源码路径

all:
	make -C $(LINUX_KERNEL_PATH) M=$(CURRENT_PATH) modules	#编译模块
#				内核的路径		  当前目录编译完放哪   表明编译的是内核模块

clean:
	make -C $(LINUX_KERNEL_PATH) M=$(CURRENT_PATH) clean	#清理模块