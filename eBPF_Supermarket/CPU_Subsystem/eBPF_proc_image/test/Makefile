.PHONY: all clean

# 默认目标
all: test_proc

# 编译生成可执行文件
test_proc: test_proc.c
	gcc $< -o $@

# 清理生成的文件
clean:
	rm -f test_proc
