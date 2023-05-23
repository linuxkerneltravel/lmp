# FUSEdemo
一个内存文件系统的fusedemo。已知可以把MongoDB或者Caffe或者Hadoop的源码或测试集拷入文件系统内，然后运行它们自带的测试集。

## 为了编译它：
### 在cmake里添加如下fuse调用:
```sh
find_package(PkgConfig)
  if (PKG_CONFIG_FOUND)
  pkg_check_modules(GTK "fuse3")
  if (GTK_FOUND)
    target_link_libraries(client ${GTK_LIBRARIES})
    add_definitions(${GTK_CFLAGS} ${GTK_CFLAGS_OTHER})
  endif()
endif()
```
### 或者将fuse加入pkg环境变量后用gcc编译：(填入你自己的fuse3.pc地址)<br>
```sh
export PKG_CONFIG_PATH=/home/fuse/libfuse/fuse3.pc:$PKG_CONFIG_PATH
ldconfig
gcc fusedemo.c -o fusedemo  `pkg-config fuse3 --cflags --libs` 
```
## 为了运行(挂载)它：
```sh
mkdir yourdir
./fusedemo ./yourdir
```
## 查看是否挂载成功
```sh
df -T yourdir//查看OS的文件系统类型
```
## 卸载
```sh
fusermount -u ./yourdir
```
