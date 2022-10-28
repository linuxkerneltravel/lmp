之前的write、read、open脚本都是通过bcc/examples/tracing/hello_perf_output.py脚本改善来的，也就是用了`perf_event`机制。
### perf_event机制
这个机制的简单来说是这样的，定义了一个用于传输数据的缓冲区，内核将采集到的数据提交到这个缓冲区，用户态再打开这个缓冲区将数据提取出来。

使用步骤如下：
1. 定义一个的结构体，用于存放要传输的数据：
```
struct data_t data{};
```
2. 定义一个perf_event对象，用于把从内核中取到的数据传输到缓冲区 ：
```
BPF_PERF_OUTPUT(events);
```
3. 提交数据到perf_event：
```
events.perf_submit(ctx, &data, sizeof(data));
```
4. 定义一个用于打印缓冲区数据的方式：
```
def print_event(cpu, data, size):
```
5. 最后在用户态打开缓冲区打印出数据：
```
b["events"].open_perf_buffer(print_event)
```

### 问题
BCC给出的hello_perf_output示例是监控"clone"系统调用，opensnoopy是监控"open"系统调用，由于perf_event涉及到调用内核的读写功能，所以用来监控write/read就会有问题：CPU使用率高，居高不下，因为读写量太大；内存泄漏，报*possibly lost xx samples*。

使用per_event机制对这几个系统调用分别测试，查看输出和资源利用率：
#### 1. open
```
b.attach_kprobe(event=b.get_syscall_fnname("open"), fn_name="hello")
```
没有输出，于是新增一条**openat**：
```
b.attach_kprobe(event=b.get_syscall_fnname("openat"), fn_name="hello")
```
##### 结果
可以正常输出，结果中没有自身程序  
初始CPU利用率在40%以下，之后稳定在3%左右  
Ctrl+C可以停止程序  

#### 2.write
```
b.attach_kprobe(event=b.get_syscall_fnname("write"), fn_name="hello")
```
##### 结果
算是非正常输出，结果中自身程序为主  
Ctrl+C无法停止程序  
CPU利用率一直在80%左右  

将自己过滤掉，CPU利用率在75%左右，效果并不好  
但是Ctrl+C可以停止程序了(有几率)  

#### 3.read
```
b.attach_kprobe(event=b.get_syscall_fnname("read"), fn_name="hello")
```
##### 结果
算是非正常输出，结果自身程序不算多  
CPU利用率一直在80%左右  
一直有*Possibly lost x samples*  
Ctrl+C无法停止程序  

将自己过滤掉，CPU利用率在75%左右，效果并不好  
CPU利用率一直在80%左右  
一直有*Possibly lost x samples*  
Ctrl+C无法停止程序  

### 解决方法
监测使用BPF_HASH，同时过滤自己的PID。