# 编译器和编译选项
CC = gcc
LDFLAGS = -pthread

# 可执行文件名
TARGET = test_mem

# 源文件
SRCS = test_mem.c

# 目标文件
OBJS = $(SRCS:.c=.o)

# 伪目标
.PHONY: all clean

# 默认目标
all: $(TARGET)

# 目标文件
$(TARGET): $(SRCS)
	$(CC) $(LDFLAGS) -o $@ $(SRCS)

# 清理目标文件和可执行文件
clean:
	rm -f $(TARGET) $(OBJS)
