### argparse
argparse是一个用于解析命令行参数的Python模块，主要有三个步骤：
创建 ArgumentParser() 对象
调用 add_argument() 方法添加参数
使用 parse_args() 解析添加的参数

1、创建 ArgumentParser() 对象
```py
parser = argparse.ArgumentParser(
    description="Trace open() syscalls",
    formatter_class=argparse.RawDescriptionHelpFormatter,
    epilog=examples)
```
ArgumentParser对象包含将命令行解析成 Python 数据类型所需的全部信息:
- prog - 程序的名称（默认：sys.argv[0]）
- usage - 描述程序用途的字符串（默认值：从添加到解析器的参数生成）
- description - 在参数帮助文档之前显示的文本（默认值：无）
- epilog - 在参数帮助文档之后显示的文本（默认值：无）
- parents - 一个 ArgumentParser 对象的列表，它们的参数也应包含在内
- formatter_class - 用于自定义帮助文档输出格式的类
- prefix_chars - 可选参数的前缀字符集合（默认值：’-’）
- fromfile_prefix_chars - 当需要从文件中读取其他参数时，用于标识文件名的前缀字符集合（默认值：None）
- argument_default - 参数的全局默认值（默认值： None）
- conflict_handler - 解决冲突选项的策略（通常是不必要的）
- add_help - 为解析器添加一个 -h/–help 选项（默认值： True）
- allow_abbrev - 如果缩写是无歧义的，则允许缩写长选项 （默认值：True）

2、添加参数
```py
parser.add_argument("-p", "--pid",
    help="trace this PID only")
```
-action - 命令行遇到参数时的动作，默认值是 store。
-type - 命令行参数应该被转换成的类型
-help - 参数的帮助信息，当指定为 argparse.SUPPRESS 时表示不显示该参数的帮助信息.
default - 不指定参数时的默认值。

3、解析添加的参数
```py
args = parser.parse_args()
```
ArgumentParser 通过 parse_args() 方法解析参数。它将检查命令行，把每个参数转换为适当的类型然后调用相应的操作。在脚本中，通常 parse_args() 会被不带参数调用，而 ArgumentParser 将自动从 sys.argv 中确定命令行参数。

### Python 字典
Python内置的数据结构之一，与列表一样是一个可变序列，字典的每个键值 key=>value 对用冒号 : 分割，每个对之间用逗号(,)分割，整个字典包括在花括号 {} 中 ,格式如下所示：
```
d = {key1 : value1, key2 : value2, key3 : value3 }
```
于是可以用这个特性来计数：
```py
def print_event(cpu, data, size):
    global dic
    event = b["events"].event(data)

    str = "%-s, %-d, %s[%-d], %d 0x%lx-0x%lx" % \
    (event.comm, event.pid, pwd.getpwuid(event.uid)[0] ,event.uid,  event.pr, event.s_addr, event.e_addr)
    if dic.get(str,-1) == -1:
        dic[str]=1
    else:
        dic[str]+=1
```

### 此外
|函数名|用法|作用|
|---|---|---|
ctypes	|	from ctypes import c_int	|	ctypes-使用c类型的数据
argv	|	from sys import argv	|	argv用来传参
PT_REGS_IP	|	PT_REGS_IP(ctx)	|	获取kernel IP
lambda	|	key=lambda counts:counts[1].value	|	lambda表示输入counts，输出counts[1].value
ksym	|	b.ksym(k.id)	|	将一个内核内存地址转成一个内核函数名字
get_syscall_fnname	|	b.get_syscall_fnname("clone")	|	获取指定系统调用函数名
trace_fields	|	(task,pid,cpu,flags,ts,msg) = b.trace_fields()	|	从trace_pipe返回固定字段集
raise	|	except:  print("引发异常")  raise	|	引发当前上下文中捕获的异常
PT_REGS_RC	|	PT_REGS_RC(ctx)	|	获取返回值
BPF_PERF_OUTPUT	|	BPF_PERF_OUTPUT(events);	|	C语言的打印到这个output然后传给python
perf_submit	|	events.perf_submit(ctx, &data, sizeof(data));	|	把event传到perf的环形缓冲区再送到用户空间
bpf_probe_read_kernel	|	bpf_probe_read_kernel(&ipv4_key.saddr, sizeof(ipv4_key.saddr),	|	读取内核结构体的成员
bpf_probe_read_user	|	bpf_probe_read_user(&query, sizeof(query), st);	|	bpf_probe_read 系列函数读取内存数据
bpf_ktime_get_ns	|	ts = bpf_ktime_get_ns();	|	获取当前时间，精确到纳秒
bpf_get_current_pid_tgid()	|	pid = bpf_get_current_pid_tgid();	|	获取当前进程pid和tgid
bpf_get_current_comm()	|	bpf_get_current_comm(&(key->name), sizeof(key->name));	|	用当前进程名字填充第一个参数地址。
bpf_get_current_task	|	task = (void*)bpf_get_current_task();	|	返回指向当前task_struct对象的指针
trace_print()	|	bpf_trace_printk("Hello, World!\\n"); return 0; }').trace_print()	|	打印出trace_pipe管道的内容
get_syscall_fnname()	|	event=b.get_syscall_fnname("clone")	|	与bpf_trace_printk对应，获取指定系统调用函数名
BPF_HASH	|	BPF_HASH(name [, key_type [, leaf_type [, size]]])	|	创建一个name哈希表，中括号中是可选参数。
attach_kprobe	|	BPF.attach_kprobe(event="event", fn_name="name")	|	使用函数入口的内核动态跟踪，关联Ｃ函数name和内核函数event()。
attach_kretprobe	|	BPF.attach_kretprobe(event="event", fn_name="name")	|	关联Ｃ函数name和内核函数event，在内核函数返回的时候调用函数name.
sorted	|	sorted(dic.items(), key=lambda item:item[1], reverse=True):	|	例子是说：对字典排序，比对的是字典的key值，倒序输出

***
（还在补充中）