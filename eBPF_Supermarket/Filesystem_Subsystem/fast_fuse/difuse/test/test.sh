#!/bin/bash

# 挂载点目录
MOUNT_POINT="../src/mountpoints"
SRC_DIR="../src"

# FUSE 可执行文件
FUSE_EXEC="../src/difuse"

echo "Compiling FUSE filesystem..."
make -C "$SRC_DIR" clean
make -C "$SRC_DIR" all

# 检查编译是否成功
if [ ! -f "$FUSE_EXEC" ]; then
    echo "Compilation failed. Exiting."
    exit 1
fi

# 创建挂载点目录（如果不存在）
if [ ! -d "$MOUNT_POINT" ]; then
    mkdir -p "$MOUNT_POINT"
fi

# 挂载 FUSE 文件系统（前台运行并显示调试信息）
echo "Mounting FUSE filesystem..."
$FUSE_EXEC -f -d "$MOUNT_POINT" &
FUSE_PID=$!
sleep 1  # 等待文件系统完全挂载

# 测试读取根目录
echo "Testing readdir on root..."
ls "$MOUNT_POINT"

# 测试读取子目录 dir1
echo "Testing readdir on dir1..."
ls "$MOUNT_POINT/dir1"

# 测试读取子目录 dir2
echo "Testing readdir on dir2..."
ls "$MOUNT_POINT/dir2"

# 测试读取文件 file1
echo "Testing read file1..."
cat "$MOUNT_POINT/dir1/file1"

# 测试读取文件 file2
echo "Testing read file2..."
cat "$MOUNT_POINT/dir1/file2"

# 测试读取文件 file3
echo "Testing read file3..."
cat "$MOUNT_POINT/dir2/file3"

# 测试打开文件
echo "Testing open file..."
if [ -e "$MOUNT_POINT/dir1/file1" ]; then
    echo "File 'file1' exists in dir1"
else
    echo "File 'file1' does not exist in dir1"
fi

if [ -e "$MOUNT_POINT/dir1/file2" ]; then
    echo "File 'file2' exists in dir1"
else
    echo "File 'file2' does not exist in dir1"
fi

if [ -e "$MOUNT_POINT/dir2/file3" ]; then
    echo "File 'file3' exists in dir2"
else
    echo "File 'file3' does not exist in dir2"
fi

# 显示调试日志
echo "FUSE debug log:"
kill -USR1 $FUSE_PID
sleep 1  # 等待日志输出

# 卸载 FUSE 文件系统
echo "Unmounting FUSE filesystem..."
sudo fusermount -u "$MOUNT_POINT"

# 等待 FUSE 进程终止
wait $FUSE_PID

echo "All tests completed."
