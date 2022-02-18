+++
title = "插件：fs/vfsstat.py"
description = "针对插件：plugins/fs/vfsstat.py 的分析"
weight = 10
+++

## 插件说明
插件地址： plugins/fs/vfsstat.py

## 插件功能说明
通过统计文件系统的读、写、同步、打开以及创建的次数来观测VFS的性能状态

## 插件代码解读
#### 具体的BPF程序
- 定义一个枚举类型stat_types并将其中的变量声明为int型，可以看出状态最大值S_MAXSTAT为7
```c
#include <uapi/linux/ptrace.h>

enum stat_types {
    S_READ = 1,
    S_WRITE,
    S_FSYNC,
    S_OPEN,
    S_CREATE,
    S_MAXSTAT
};
```

- BPF_ARRAY用于跟踪收到的数据包总数
```c
BPF_ARRAY(stats, u64, S_MAXSTAT);
```

- 定义一个自增函数stats_increment，会根据参数key的类型来查找并进行自增

```c
static void stats_increment(int key) {
    u64 *leaf = stats.lookup(&key);
    if (leaf) (*leaf)++;
}
```
  
- 函数do_read执行参数key为S_READ时的数据包统计；
函数do_write执行参数key为S_WRITE时的数据包统计；
函数do_fsync执行参数key为S_FSYNC时的数据包统计；
函数do_open执行参数key为S_OPEN时的数据包统计；
函数do_create执行参数key为S_CREATE时的数据包统计.
```c
void do_read(struct pt_regs *ctx) { stats_increment(S_READ); }
void do_write(struct pt_regs *ctx) { stats_increment(S_WRITE); }
void do_fsync(struct pt_regs *ctx) { stats_increment(S_FSYNC); }
void do_open(struct pt_regs *ctx) { stats_increment(S_OPEN); }
void do_create(struct pt_regs *ctx) { stats_increment(S_CREATE); }
```

#### 关联到内核函数
kprobe程序允许在执行内核函数之前插入BPF程序。当内核执行到kprobe挂载的内核函数时，先运行BPF程序，BPF程序运行结束后，返回继续开始执行内核函数。
```c
b.attach_kprobe(event="vfs_read", fn_name="do_read")
b.attach_kprobe(event="vfs_write", fn_name="do_write")
b.attach_kprobe(event="vfs_fsync", fn_name="do_fsync")
b.attach_kprobe(event="vfs_open", fn_name="do_open")
b.attach_kprobe(event="vfs_create", fn_name="do_create")
```

以第一条语句为例：
- `b.attach_kprobe()`：指定了该BPF程序类型为kprobe；
- `event="vfs_read"`：指定了kprobe挂载的内核函数为vfs_read；
  内核函数的原型如下：
    ```c
    ssize_t vfs_read(struct file* filp, char __user* buffer, size_t len, loff_t* pos);

    ssize_t vfs_write(struct file* filp, const char __user* buffer, size_t len, loff_t* pos);
    ```
- `fn_name="do_read"`：指定了当检测到内核函数vfs_read时，即当内核函数vfs_read有返回值时，执行fn_name所指定的函数do_read。

其余语句同理。


## 插件使用

### 后台运行方式
使用后台运行的方式需要引入以下打印语句：
```py
# 每列的标签以及下标
stat_types = {
    "READ": 1,
    "WRITE": 2,
    "FSYNC": 3,
    "OPEN": 4,
    "CREATE": 5
}

# 经过interval秒输出一次，这里interval定义为1
i = 0
print("  TIME     READ WRITE CREATE OPEN  FSYNC")
while (1):
    if count > 0:
        i += 1
        if i > count:
            exit()
    try:
        sleep(interval)
    except KeyboardInterrupt:
        pass
        exit()
    
    print("%-8s: " % strftime("%H:%M:%S"), end="")
    
# 按列打印
    vfs_list = [0,0,0,0,0,0]
    times=1
    for stype in stat_types.keys():
        idx = stat_types[stype]
        try:
            val = b["stats"][c_int(idx)].value / interval
        except:
            val = 0
        vfs_list[times] = val
        times += 1
        if times == 5:
            times=0
    print(vfs_list[1],vfs_list[2],vfs_list[3],vfs_list[4],vfs_list[5])
```
在命令行使用python执行该脚本：
> $ sudo python vfsstat.py

结果如下：
```
  TIME     READ WRITE CREATE OPEN  FSYNC
10:41:01:  0.0  45.5  23.0   0.0   0
10:41:02:  0.0  16.5  16.5   0.0   0
10:42:03:  0.0  5.5   13.0   0.0   0
10:42:04:  0.0  7.0   2.5    0.0   0
10:42:05:  0.0  22.0  12.0   0.0   0

```

### web 运行方式
使用web方式需要加入以下语句：
- 引入包
```py
from const import DatabaseType
from init_db import influx_client
from db_modules import write2db
```

- 定义存储结构
```py
data_struct = {"measurement":'vfsstatTable',
                "tags":['glob'],
                "fields":['total_read','total_write','total_create','total_open','total_fsync']}

class test_data(object):
    def __init__(self,a,b,c,d,e,f):
            self.glob = a
            self.total_read = b
            self.total_write = c
            self.total_fsync = d
            self.total_open = e
            self.total_create = f
```

- 数据传递到数据库
```py
data = test_data('glob', vfs_list[1],vfs_list[2],vfs_list[3],vfs_list[4],vfs_list[5])
write2db(data_struct, data, influx_client, DatabaseType.INFLUXDB.value)
```

在lmp界面提交vfsstat：

![avatar](images/1.png)

点击submit后转到grafana页面查看：

![avatar](images/2.png)


## 插件运行版本
### 插件适用版本
Ubuntu 20.04 5.4.0-77-generic
Ubuntu 18.04 5.4.0-90-generic


### 已经测试过的版本
Ubuntu 20.04 5.4.0-77-generic
Ubuntu 18.04 5.4.0-90-generic


## 额外说明
无