#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "fs_watcher.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, pid_t);
	__type(value, struct fs_t);
} data SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries,256 * 1024);
} rb SEC(".maps");

SEC("kprobe/vfs_write")
int kprobe_vfs_write(struct pt_regs *ctx)
{
  struct fs_t fs_data = {};
  pid_t pid;
  unsigned long inode_number;//定义用于存储inode号码的变量

  //探测的是第一个参数，文件指针,读取inode_number
  struct file *filp = (struct file *)PT_REGS_PARM1(ctx); 
  if (!filp) {
        bpf_printk("Failed to read file pointer\n");
        return 0;
  }

  unsigned int flags = BPF_CORE_READ(filp, f_flags);

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

  // 使用 BPF_CORE_READ 获取文件权限
  mode_t mode = BPF_CORE_READ(inode, i_mode);

  //读取inode的i_ino字段
  int ret = bpf_probe_read_kernel(&inode_number,sizeof(inode_number),&inode->i_ino);
  if (ret != 0) {
        bpf_printk("Failed to read inode number\n");
        return 0;
  }

  //探测的是第三个参数，要写入的字节数
  size_t count = (size_t)PT_REGS_PARM3(ctx);
  
  pid = bpf_get_current_pid_tgid() >> 32;
  
  // 获取进程名称
  bpf_get_current_comm(fs_data.comm, sizeof(fs_data.comm));
  
  //将参数信息保存到哈希表中
  fs_data.pid = pid;
  fs_data.count = count;
  fs_data.inode_number = inode_number;
  fs_data.mode = mode;
  fs_data.flags = flags;

  bpf_map_update_elem(&data, &pid, &fs_data, BPF_ANY);
  return 0;
}

// kretprobe 钩子，探测 vfs_write 返回点，获取实际的写入字节数
SEC("kretprobe/vfs_write")
int kretprobe_vfs_write_ret(struct pt_regs *ctx)
{
  pid_t pid;
  struct fs_t *fs_data;
  size_t real_count = PT_REGS_RC(ctx); // 获取返回值，即实际写入的字节数

  // 获取当前进程的 PID
  pid = bpf_get_current_pid_tgid() >> 32;

  // 从哈希表中读取之前保存的参数信息
  fs_data = bpf_map_lookup_elem(&data, &pid);
  if (!fs_data) {
    bpf_printk("Failed to retrieve fs data\n");
    return 0;
  }

  // 创建事件并保存返回值
  struct fs_t *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
  if (!e) {
    bpf_printk("Failed to reserve space in ringbuf\n");
      return 0;
  }

  e->pid = pid;
  e->real_count = real_count;
  e->count = fs_data->count;
  e->inode_number = fs_data->inode_number;
  e->flags = fs_data->flags;
  e->mode = fs_data->mode;

  bpf_probe_read_str(e->comm, sizeof(e->comm), fs_data->comm);

  // 提交事件
  bpf_ringbuf_submit(e, 0);

  // 从哈希表中删除已处理的记录
  bpf_map_delete_elem(&data, &pid);
  return 0;
}