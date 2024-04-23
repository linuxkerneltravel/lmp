## 获取容器内系统调用

Tracepoint是内核代码中的一种静态标记，是开发者在内核源代码中散落的一些hook，开发者可以依托这些hook实现相应的追踪代码插入。开发者在/sys/kernel/debug/tracing/events/目录下，可以查看当前版本的内核支持的所有Tracepoints，在每一个具体Tracepoint目录下，都会有一系列对其进行配置说明的文件，比如可以通过enable中的值，来设置该Tracepoint探针的开关等。和Kprobes相比，区别在于Tracepoints是内核开发人员已经在内核代码中提前埋好的。

查看`raw_syscalls`:`sys_enter`的format信息:

```
$ cat /sys/kernel/tracing/events/raw_syscalls/sys_enter/format 
name: sys_enter
ID: 348
format:
        field:unsigned short common_type;       offset:0;       size:2; signed:0;
        field:unsigned char common_flags;       offset:2;       size:1; signed:0;
        field:unsigned char common_preempt_count;       offset:3;       size:1; signed:0;
        field:int common_pid;   offset:4;       size:4; signed:1;

        field:long id;  offset:8;       size:8; signed:1;
        field:unsigned long args[6];    offset:16;      size:48;        signed:0;

print fmt: "NR %ld (%lx, %lx, %lx, %lx, %lx, %lx)", REC->id, REC->args[0], REC->args[1], REC->args[2], REC->args[3], REC->args[4], REC->args[5]

```

BCC Tracepoint探针的实现:

```c
TRACEPOINT_PROBE(raw_syscalls, sys_enter) {
    struct task_struct *curr_task = (struct task_struct *)bpf_get_current_task();
    if(get_level(curr_task)){
        struct syscall_key_t k = {.argsid = args->id};
        get_cont_id(curr_task,k.cid);
        syscalls.increment(k,1);
    }
    return 0;
}
```

### 参考文献

https://blog.csdn.net/jasonactions/article/details/123470620
