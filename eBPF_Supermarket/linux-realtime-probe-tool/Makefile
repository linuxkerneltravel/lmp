obj-m+=irq_mod.o
irq_mod-objs:=src/data.o src/kfifo.o src/kprobe.o src/proc.o src/objpool.o src/percpu.o src/workqueue.o src/kthread.o src/xarray.o main.o #
CURRENT_PATH:=$(shell pwd)
LINUX_KERNEL:=$(shell uname -r)
LINUX_KERNEL_PATH:=/usr/src/linux-headers-$(LINUX_KERNEL)
all:
	make -C $(LINUX_KERNEL_PATH) M=$(CURRENT_PATH) modules
clean:
	make -C $(LINUX_KERNEL_PATH) M=$(CURRENT_PATH) clean
