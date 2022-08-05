DEBUG ?= 0
CC=clang
#CFLAGS=-O2 -g -Wall -target bpf -I/usr/include/$(shell uname -m)-linux-gnu -I/usr/src/linux-headers-5.4.0-121/include -I/usr/src/linux-headers-5.4.0-121/arch/x86/include
CFLAGS=-O2 -g -Wall -target bpf -I/usr/include/$(shell uname -m)-linux-gnu

xdp_dns_kern:
	$(CC) $(CFLAGS) -c xdp_dns_kern.c -o xdp_dns_kern.o

clean:
	rm -f *.o
	rm -f *.ll
	rm -f *~
