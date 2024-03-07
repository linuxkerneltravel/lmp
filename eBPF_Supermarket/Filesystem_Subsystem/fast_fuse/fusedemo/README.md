# fusedemo：a simple file system based on the fuse library

## 安装相关依赖并获取libfuse库：

```
sudo apt-get install fuse libfuse-dev meson wget
git clone https://github.com/libfuse/libfuse/releases/tag/fuse-3.16.2/fuse-3.16.2.tar.gz
tar -zxvf fuse-3.16.2.tar.gz
mv fuse-3.16.2.tar.gz libfuse
cd libfuse
```

## 将fusedemo.c和Makefile文件复制到相应目录下：

```
cp /path/to/fusedemo.c ./example/
cp /path/to/make.sh ./
```

## 编译libfuse库并构建项目：

```
mkdir build
cd build
meson ..
//查看meson的设置并配置
meson configure
meson configure -D disable-mtab=true
//编译linfuse库
ninja
sudo ninja install
```

## 运行(挂载)：

```
cd ./example/
mkdir yourdir
./fusedemo yourdir
```

## 查看是否挂载成功：

```
//查看OS的文件系统类型
df -T yourdir
```

## 执行文件操作：

```
cd yourdir
ls
touch
mkdir
cat 
tree
[...]
```

## 卸载：

```
fusermount -u yourdir
```

