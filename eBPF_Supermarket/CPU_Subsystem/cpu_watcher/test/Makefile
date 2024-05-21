CC = gcc
CFLAGS = -Wall -Wextra
LDFLAGS = -lrt

.PHONY: all clean

all:  test_cpuwatcher sender receiver

sender: mq_test_sender.c
	$(CC) $(CFLAGS) -o sender mq_test_sender.c $(LDFLAGS)

receiver: mq_test_receiver.c
	$(CC) $(CFLAGS) -o receiver mq_test_receiver.c $(LDFLAGS)

test_cpuwatcher: test_cpuwatcher.c
	$(CC) $(CFLAGS) -o test_cpuwatcher test_cpuwatcher.c
clean:
	rm -f test_cpuwatcher sender receiver
