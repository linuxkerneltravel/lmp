#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "fs_watcher.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";
#define PATH_MAX 256
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


SEC("kprobe/vfs_write")
int kprobe_vfs_write(struct pt_regs *ctx)
{
  pid_t pid;
  struct fs_t *e;
  unsigned long inode_number;//定义用于存储inode号码的变量

   //探测的是第一个参数，文件指针,读取inode_number
  struct file *filp = (struct file *)PT_REGS_PARM1(ctx);  
  struct dentry *dentry = BPF_CORE_READ(filp,f_path.dentry);
  if(!dentry){
		bpf_printk("Failed to read dentry\n");
		return 0;
	}
  struct inode *inode = BPF_CORE_READ(dentry,d_inode);
  if(!inode){
    bpf_printk("Failed to read inode\n");
    return 0;
  }
  int ret = bpf_probe_read_kernel(&inode_number,sizeof(inode_number),&inode->i_ino);

  //探测的是第三个参数，要写入的字节数
  size_t count = (size_t)PT_REGS_PARM3(ctx);
  
  //这是vfs_write的返回值，它是一个实际写入的字节数
  size_t real_count = PT_REGS_RC(ctx);
  
  pid = bpf_get_current_pid_tgid() >> 32;
  e = bpf_ringbuf_reserve(&rb,sizeof(*e),0); 
  if(!e)
    return 0;
  
  e->pid = pid;
  e->real_count = real_count;
  e->count = count;
  e->inode_number = inode_number;

  //这里将获取到的文件指针不为空时
  bpf_ringbuf_submit(e, 0);
  return 0;
}