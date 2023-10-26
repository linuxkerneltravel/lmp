# fusedemo：a simple file system based on the fuse library

## 编译：

### 将fuse加入pkg环境变量后用gcc编译：(填入你自己的fuse3.pc地址)

```
export PKG_CONFIG_PATH=/path/to/fuse3.pc:$PKG_CONFIG_PATH
ldconfig
gcc fusedemo.c -o fusedemo  `pkg-config fuse3 --cflags --libs` 
```

## 运行(挂载)：

```
mkdir yourdir
./fusedemo yourdir
```

## 查看是否挂载成功：

```
//查看OS的文件系统类型
df -T yourdir
```

## 卸载：

```
fusermount -u yourdir
```

