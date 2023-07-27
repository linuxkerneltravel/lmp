obj-m += mutex_test1.o

CURRENT_PATH:=$(shell pwd)	#模块所在的当前所在路径
LINUX_KERNEL:=$(shell uname -r)	#linux内核代码的当前版本
LINUX_KERNEL_PATH:=/usr/src/linux-headers-$(LINUX_KERNEL)	#linux内核的当前版本源码路径

all:
	make -C $(LINUX_KERNEL_PATH) M=$(CURRENT_PATH) modules	#编译模块
#				内核的路径		  当前目录编译完放哪   表明编译的是内核模块

clean:
	make -C $(LINUX_KERNEL_PATH) M=$(CURRENT_PATH) clean	#清理模块