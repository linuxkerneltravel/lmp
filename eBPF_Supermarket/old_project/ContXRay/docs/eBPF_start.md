## 基于kprobe程序类型的eBPF程序的第一个入门程序

#### Linux eBPF编程环境搭建过程、环境搭建常见的各种报错与解决方法
环境搭建参照[Linux内核之旅-BPF C编程入门](https://www.bilibili.com/video/BV1f54y1h74r)，这里以内核5.4.0版为例整理如下：

1. 下载内核源码:
   搜索与自己系统版本相同的内核源码
   > \# apt-cache search linux-source    

   安装源码
   > \# apt install linux-source-[your version]  
   
   如果搜索不到就登录以下网站下载与自己内核版本对应的源码包
   <http://ftp.sjtu.edu.cn/sites/ftp.kernel.org/pub/linux/kernel>

   将源码包拷贝至/usr/src目录并解压源码包
   （gz包使用-zxvf参数，bz包使用-jxvf参数）
   > \# cd /usr/src/
   > \# tar -zxvf linux-5.4.tar.gz 

2. 配置环境：
   更新安装路径并安装依赖包
   > \# apt update
   > \# apt install libncurses5-dev flex bison libelf-dev binutils-dev libssl-dev

   安装编译环境
   > \# apt install clang llvm

3. 配置内核：
   进入源码目录
   > \# cd /usr/src/linux-5.4

   生成config文件
   > \# make defconfig
   > \# ll .config

   提前避免**scripts/mod/modpost: not found**报错
   > \# make modules_prepare

   关联内核头文件
   > \# make headers_install

   编译bpf样例
   > \# make M=samples/bpf
   

4. 一些报错解决：
    1）执行`make M=samples/bpf`报错 **scripts/mod/modpost: not found**，解决方式如下：
   > \# make modules_prepare

   或者执行
   > \# make script

   之后重新执行执行后续步骤即可。
&nbsp;
    2）执行`make M=samples/bpf`报错 **'asm/mmiowb.h' file not found**
   可归结到/modpost: not found错误。  
&nbsp;
    3）执行`make modules_prepare`报错 **openssl/bio.h: No such file or directory**
    libssl-dev安装未成功，我的报错是*地址404 not found*，表示需要更新apt下载路径`apt update`，重新安装`apt install libssl-dev`，之后重新依次执行后续步骤。
&nbsp;
    4）报错 **/tools/perf/perf-sys.h:‘test_attr__enabled’ undeclared**，步骤如下：
   > \# cd /usr/src/linux-5.4/tools/perf

   备份原头文件
   > \# cp perf-sys.h perf-sys.h_bak

   修改新头文件
   > \# vim perf-sys.h

   在主函数前增加以下定义：
   ```c
    #ifndef HAVE_ATTR_TEST
    #define HAVE_ATTR_TEST 0
    #endif
   ```

   将原71行的`#ifdef HAVE_ATTR_TEST`改为` #if HAVE_ATTR_TEST`

   修改后的配置文件参照以下：
   <https://github.com/nevermosby/linux-bpf-learning/blob/master/bpf/perf-sys.h>

   之后重新执行执行`make M=samples/bpf`即可。
<br>
5. 执行样例：
   进入bpf样例目录
   > \# cd samples/bpf

   可以看到已经生成了可执行文件
   > \# ll sock_example*
    -rwxr-xr-x 1 root root 17100 Mar 17 21:00 sock_example*
    -rw-r--r-- 1 root root  2925 Jan 28  2018 sock_example.c
    -rw-r--r-- 1 root root   834 Jan 28  2018 sock_example.h
    -rw-r--r-- 1 root root  3652 Mar 17 21:00 sock_example.o

   执行一个案例
   > \# ./sock_example 
    TCP 0 UDP 0 ICMP 0 packets
    TCP 0 UDP 0 ICMP 0 packets
    TCP 0 UDP 0 ICMP 4 packets
    TCP 0 UDP 56 ICMP 8 packets
    TCP 0 UDP 56 ICMP 12 packets
    TCP 0 UDP 80 ICMP 16 packets
    TCP 0 UDP 96 ICMP 16 packets
    TCP 0 UDP 184 ICMP 16 packets
    TCP 0 UDP 200 ICMP 16 packets
    TCP 0 UDP 200 ICMP 16 packets

    程序可正常运行即表示环境搭建成功。
    
#### Linux eBPF编程案例：hello world
进入bpf目录：
> \# cd /usr/src/linux-5.4/samples/bpf

1) 首先编写一个运行在内核态的c程序，它用BPF程序来跟踪一个函数，通过clang编译完成后会生成BPF字节码，功能是在函数被调用的时候在终端打印一句“Hello world”，代码如下：
    ```c
    #include <uapi/linux/bpf.h>
    #include "bpf_helpers.h"

    SEC("tracepoint/syscalls/sys_enter_execve")
    int bpf_prog(void *ctx)
    {
        char msg[] = "Hello World \n";
        bpf_trace_printk(msg, sizeof(msg));

        return 0;
    }
    char _license[] SEC("license") = "GPL";
    ```
    SEC表示用静态追踪tracepoint的方式跟踪系统调用execve，即检测到终端的任何操作后便调用bpf程序。  
    这里也可以使用动态追踪kprobe的方式，替换为如下语句：
    ```c
    SEC("kprobe/sys_write")
    ```
    表示追踪系统调用write，同样也可以替换为任何别的函数。
&nbsp;
2) 其次编写一个运行在用户态的c程序，它的主要作用是把BPF字节码加载到内核中，代码如下：
    ```c
    #include "bpf_load.h"

    int main(void)
    {
        if(load_bpf_file("hello_kern.o"))
            return -1;
        read_trace_pipe();

        return 0;
    }
    ```

3) 修改bpf目录的MakeFile文件，在原有内容末尾直接追加就行：  
    在注释处`# List of programs to build`部分的末行添加：
    ```c 
    hostprogs-y += hello 
    ```
    在注释处`# Libbpf dependencies`部分的末行添加：
    ```c 
    hello-objs := bpf_load.o hello_user.o
    ```
    在注释处`# Tell kbuild to always build the programs`部分的末行添加：
    ```c 
    always += hello_kern.o
    ```
4) 编译运行
   回到源码目录
   > \# cd /usr/src/linux-5.4/

   编译
   > \# make M=samples/bpf

   回到bpf目录查看生成文件
   > \# cd samples/bpf
   > \# ll hello*
    -rwxr-xr-x 1 root root 372360 Mar 21 18:09 hello*
    -rw-r--r-- 1 root root    273 Mar 21 18:12 hello_kern.c
    -rw-r--r-- 1 root root   1040 Mar 21 18:13 hello_kern.o
    -rw-r--r-- 1 root root    123 Mar 21 17:51 hello_user.c
    -rw-r--r-- 1 root root   1768 Mar 21 18:09 hello_user.o

   执行
   > \# ./hello

   在另一个终端执行top命令，从输出中看到top进程的PID为88869，hello进程的运行会有如下输出：
   >  bash-88869   [001] .... 219435.494179: 0: Hello World

   可以看到bpf程序成功追踪到了top命令并打印了“Hello World”。

