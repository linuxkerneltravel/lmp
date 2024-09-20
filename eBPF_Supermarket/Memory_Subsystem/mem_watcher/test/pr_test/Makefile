# Compiler and flags
CC = gcc
CFLAGS = -Wall

# Source files
C_SRC = pr_test.c

# Output binary
C_OUT = pr_test

.PHONY: all clean run

all: $(C_OUT)

$(C_OUT): $(C_SRC)
	$(CC) $(CFLAGS) $< -o $@

clean:
	rm -f $(C_OUT)

run: $(C_OUT)
	sudo ./$(C_OUT)
