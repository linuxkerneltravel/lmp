DEBUG ?= 0
CC=clang
CFLAGS=-O2 -g -Wall -target bpf -I/usr/include/$(shell uname -m)-linux-gnu

xdp_root:
	$(CC) $(CFLAGS) -c xdp_root.c -o xdp_root.o -DDDOS_ROOT_INDEX=$(ROOT)

clean:
	rm -f *.o
	rm -f *.ll
	rm -f *~
