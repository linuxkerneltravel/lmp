CC = gcc
CFLAGS = -Wall -O2
TARGET = sysstat_test

all: $(TARGET)

$(TARGET): sysstat_test.c
	$(CC) $(CFLAGS) -o $(TARGET) sysstat_test.c

clean:
	rm -f $(TARGET)
