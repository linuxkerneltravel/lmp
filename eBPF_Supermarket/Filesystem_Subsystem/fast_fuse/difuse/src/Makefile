# Makefile for FUSE difuse example

# Compiler
CC = gcc

# Compiler flags
CFLAGS = -Wall `pkg-config fuse3 --cflags`

# Linker flags
LDFLAGS = `pkg-config fuse3 --libs`

# Source files
SRCS = difuse.c

# Output executable
TARGET = difuse

# Build target
all: $(TARGET)

# Rule to build the target
$(TARGET): $(SRCS)
	$(CC) $(CFLAGS) -o $(TARGET) $(SRCS) $(LDFLAGS)

# Clean rule
clean:
	rm -f $(TARGET)

.PHONY: all clean
