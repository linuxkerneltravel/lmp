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

SEC("kretprobe/do_sys_openat2")
int BPF_KRETPROBE(do_sys_openat2_exit,long fd)
{
  struct fs_t *e;
  pid_t pid;
 
  pid = bpf_get_current_pid_tgid() >> 32;

  bpf_map_update_elem(&data,&pid,&fd,BPF_ANY);
}

SEC("kprobe/vfs_write")
int BPF_KPROBE(vfs_write)
{
  struct fs_t *e;
  int *fd_ptr;
  pid_t pid;

  pid = bpf_get_current_pid_tgid() >> 32;
  
  fd_ptr = bpf_map_lookup_elem(&data,&pid);

  e = bpf_ringbuf_reserve(&rb,sizeof(*e),0);
  if(!e)
    return 0;
  
  if(fd_ptr){
    int fd_value = *fd_ptr;
    e->fd = fd_value;
    e->pid = pid;
  } 
  bpf_ringbuf_submit(e,0);
 
  return 0;
}
