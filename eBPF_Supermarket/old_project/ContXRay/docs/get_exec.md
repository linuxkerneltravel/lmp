### 监控exec

为了获取到容器内可疑进程的执行，需要监控execve系统调用

```c
SYSCALL_DEFINE3(execve,
		const char __user *, filename,
		const char __user *const __user *, argv,
		const char __user *const __user *, envp)
{
	return do_execve(getname(filename), argv, envp);
}
```

其中，`filename`为要执行的文件名，`argv`为执行的参数，我们需要拿到这两项数据。

通过kprobe挂载到execve系统调用执行点

```python
b.attach_kprobe(event=b.get_syscall_fnname("execve"),fn_name='syscall__execve')
```

```c
struct exec_info {
    u32 pid;
    char comm[TASK_COMM_LEN];
    char filename[FILENAME_LEN];
    char argv[ARGV_LEN];
    char cid[CONTAINER_ID_LEN];
};

BPF_PERF_OUTPUT(exec_event);

int syscall__execve(struct pt_regs *ctx,const char __user *filename,const char __user *const __user *__argv){
    struct task_struct *curr_task = (struct task_struct *)bpf_get_current_task();
    if(get_level(curr_task)){
        struct exec_info info = {.pid = (u32)curr_task->pid};
        const char * _argv;
        bpf_probe_read_kernel_str(info.comm,TASK_COMM_LEN,curr_task->comm);
        bpf_probe_read_user_str(info.filename,FILENAME_LEN,filename);
        bpf_probe_read_user(&_argv,sizeof(void *),&__argv[1]);
        bpf_probe_read_user_str(info.argv,ARGV_LEN,_argv);
        get_cont_id(curr_task,info.cid);
        exec_event.perf_submit(ctx, &info, sizeof(info));
     }
     return 0;
}
```

这里一共拿出来了5项内容，分别是执行exec的进程的pid、comm，其所在的容器的id，以及执行exec的文件名、参数。