#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "write.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, pid_t);
	__type(value, int);
} data SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries,256 * 1024);
} rb SEC(".maps");

SEC("kprobe/do_sys_openat2")
int BPF_KPROBE(do_sys_openat2)
{
  int value = 1;
  struct fs_t *e;
  pid_t pid;

  pid = bpf_get_current_pid_tgid() >> 32;
  int fd = PT_REGS_RC(ctx);
  if(fd >= 0){
    //将PID和文件描述符存入哈希映射
    e->fd = fd;
    bpf_map_update_elem(&data,&pid,&value,BPF_ANY);
  }
  return 0;
}


SEC("kprobe/vfs_write")

int kprobe_vfs_write(struct pt_regs *ctx)
{
  struct file *filp;
  pid_t pid;
  struct fs_t *e;
  int *fd_ptr;

  //探测的是第一个参数，文件指针
  filp = PT_REGS_PARM1(ctx);

  //探测的是第三个参数，要写入的字节数
  size_t count = (size_t)PT_REGS_PARM3(ctx);
  
  //这是vfs_write的返回值，它是一个实际写入的字节数
  size_t real_count = PT_REGS_RC(ctx);
  
  pid = bpf_get_current_pid_tgid() >> 32;

  fd_ptr = bpf_map_lookup_elem(&data,&pid);
  
  e = bpf_ringbuf_reserve(&rb,sizeof(*e),0);

  if(!e)
    return 0;
  //这里将获取到的文件指针不为空时
  if(fd_ptr){
    int fd = *fd_ptr;
    e->fd = fd;
    e->real_count = real_count;
    e->count = count;
    e->pid = pid;
  }
  return 0;
}