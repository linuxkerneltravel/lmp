CLANG ?= clang-10
LLVM_STRIP ?= llvm-strip-12
ARCH := x86

INCLUDES := -I/usr/include -I/usr/include/x86_64-linux-gnu -I/home/shi/linux-5.15.41/tools/lib 

LIBS_DIR := -L/usr/lib64 -L/usr/lib/x86_64-linux-gnu  -L/home/shi/try/src/lib
LIBS := -lbpf -lelf

.PHONY: all clean run

all: lsm.skel.h lsm.bpf.o lsm

run: all
	sudo ./lsm

clean:
	rm -f *.o
	rm -f lsm.skel.h

lsm.bpf.o: lsm.bpf.c
	$(CLANG) -g -O2 -Wall -target bpf -D__KERNEL__ -D__TARGET_ARCH_$(ARCH) $(INCLUDES) -c $< -o $@
	$(LLVM_STRIP) -g $@ # Removes debug information

lsm.skel.h: lsm.bpf.o
	sudo bpftool gen skeleton $< > $@

lsm: lsm.c lsm.skel.h
	$(CC) -g -Wall -c $< -o $@.o
	$(CC) -g -o $@ $(LIBS_DIR) $@.o $(LIBS)

.DELETE_ON_ERROR:
