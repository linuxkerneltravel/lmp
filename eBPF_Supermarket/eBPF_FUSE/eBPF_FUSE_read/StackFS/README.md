# StackFS：Simple ExtFUSE file system to test ExtFUSE functionality

**需要使用修改过的 libfuse和 extfuse库才能将 ExtFUSE 支持添加到 StackFS 中。**

## 进入目录，进行编译：

```
$ cd StackFS
$ make
```

## 设置环境变量：

```c
$ export LIB_PATH=$HOME/libfuse/lib/.libs:$HOME/extfuse
```

## 运行(挂载)：

```c
$ sudo sh -c "LD_LIBRARY_PATH=$LIB_PATH ./StackFS_ll -o max_write=131072 -o writeback_cache -o splice_read -o splice_write -o splice_move -r $ROOT_DIR $MNT_DIR -o allow_other"
```

## 挂在成功结果：

```c
asdf@ubuntu:~/Desktop/StackFS$ sudo sh -c "LD_LIBRARY_PATH=$EXTFUSE_REPO_PATH ./StackFS_ll -o max_write=131072 -o writeback_cache -o splice_read -o splice_write -o splice_move -r $ROOT_DIR $MNT_DIR -o allow_other"
[sudo] password for asdf: 
Multi Threaded : 1
loading extfuse prog event 1
loading extfuse prog event 3
loading extfuse prog event 15
loading extfuse prog event 16
loading extfuse prog event 4
loading extfuse prog event 22
loading extfuse prog event 25
loading extfuse prog event 12
loading extfuse prog event 11
loading extfuse prog event 10
	ExtFUSE eBPF bytecode loaded: ctxt=0x7f43b8021af0 fd=11


```

并且在进入到/mnt/目录下，可以执行对文件的正常操作。

## 卸载：

按control+c即可解除挂载状态。