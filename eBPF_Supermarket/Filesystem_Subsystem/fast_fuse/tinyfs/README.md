# tinyfs：300行代码带你实现一个Linux文件系统


su root

## 编译：

```c
cd tinyfs/
make
```

## 插入内核模块并挂载：

```c

insmod ./tinyfs.ko
mount -t tinyfs none /mnt
```

## 查看是否挂载成功：

```c
//查看OS的文件系统类型
df -T /mnt
```

## 执行文件操作：

```c
//进入/mnt挂载目录
cd /mnt
//执行对文件的各项操作
ls
echo
mkdir
cat 
tree
[...]
```

## 卸载并删除内核模块：

```
//退出/mnt挂载目录
cd ..
//卸载tinyfs文件系统
umount /mnt	//-f：强制卸载选项
//删除内核模块
rmmod ./tinyfs
```

