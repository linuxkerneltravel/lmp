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

# 确保脚本退出时卸载文件系统
trap "fusermount -u $MOUNT_POINT" EXIT

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

# 进行写入测试
echo "测试文件内容写入..."
echo "Hello, this is a write test!" > $MOUNT_POINT/dir1/file1

# 进行读取测试
echo "读取文件内容:"
cat $MOUNT_POINT/dir1/file1

# 验证写入是否正确
FILE_CONTENT=$(cat $MOUNT_POINT/dir1/file1)
if [ "$FILE_CONTENT" == "Hello, this is a write test!" ]; then
    echo "文件写入和读取成功。"
else
    echo "文件写入或读取失败！"
fi

# 删除文件
echo "删除文件 $MOUNT_POINT/dir1/file1 和 $MOUNT_POINT/dir2/file3..."
rm $MOUNT_POINT/dir1/file1
rm $MOUNT_POINT/dir2/file3

# 验证文件删除
echo "验证文件删除后的结构:"
ls -l $MOUNT_POINT/dir1
ls -l $MOUNT_POINT/dir2

# 尝试删除非空目录
echo "尝试删除非空目录 $MOUNT_POINT/dir1 (应失败)..."
rmdir $MOUNT_POINT/dir1 || echo "无法删除非空目录 $MOUNT_POINT/dir1, 操作成功。"

# 删除剩余文件
rm $MOUNT_POINT/dir1/file2

# 删除空目录
echo "删除空目录 $MOUNT_POINT/dir1 和 $MOUNT_POINT/dir2..."
rmdir $MOUNT_POINT/dir1
rmdir $MOUNT_POINT/dir2

# 验证目录删除
echo "验证目录删除后的结构:"
ls -l $MOUNT_POINT
