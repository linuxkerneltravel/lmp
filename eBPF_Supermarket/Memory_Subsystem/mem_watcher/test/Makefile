CC = gcc
CFLAGS = -g

.PHONY: all clean

all: test_mem

test_mem: test_mem.c
	$(CC) $(CFLAGS) -o test_mem test_mem.c

clean:
	rm -f test_mem
