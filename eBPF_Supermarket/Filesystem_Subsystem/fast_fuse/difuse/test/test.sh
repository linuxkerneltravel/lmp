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
sleep 2  # 等待文件系统完全挂载

# 创建目录
mkdir $MOUNT_POINT/dir1
mkdir $MOUNT_POINT/dir2

# 创建文件
touch $MOUNT_POINT/dir1/file1
touch $MOUNT_POINT/dir1/file2
touch $MOUNT_POINT/dir2/file3

# 验证结构
echo "创建的目录和文件结构:"
ls -l $MOUNT_POINT

# 确保脚本退出时卸载文件系统
trap "fusermount -u $MOUNT_POINT" EXIT
