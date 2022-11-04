#include <linux/bpf.h>
#include <linux/capability.h>
#include <linux/errno.h>
#include <linux/sched.h>
#include <linux/types.h>

#include <bpf/bpf_tracing.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

#define O_NONBLOCK	00004000

typedef unsigned int gfp_t;
#ifdef CONFIG_64BIT
# define DNAME_INLINE_LEN 32 /* 192 bytes */
#else
# ifdef CONFIG_SMP
#  define DNAME_INLINE_LEN 36 /* 128 bytes */
# else
#  define DNAME_INLINE_LEN 40 /* 128 bytes */
# endif
#endif


struct pt_regs {
	long unsigned int di;
	long unsigned int orig_ax;
} __attribute__((preserve_access_index));

typedef struct kernel_cap_struct {
	__u32 cap[_LINUX_CAPABILITY_U32S_3];
} __attribute__((preserve_access_index)) kernel_cap_t;

struct cred {
	kernel_cap_t cap_effective;
} __attribute__((preserve_access_index));



struct qstr {
	const unsigned char *name;

} __attribute__((preserve_access_index));

struct dentry{
	struct qstr d_name;
	unsigned char d_iname[DNAME_INLINE_LEN];	/* small names */
} __attribute__((preserve_access_index));


struct path{
	struct dentry *dentry;

} __attribute__((preserve_access_index));

struct inode {
	long long			i_size;
} __attribute__((preserve_access_index));


struct file {
	const struct cred	*f_cred;
	unsigned int 		f_flags; 
	struct path             f_path;	
	struct inode		*f_inode;

} __attribute__((preserve_access_index));

struct fdtable {
	struct file  **fd;      /* current fd array */
} __attribute__((preserve_access_index));

struct files_struct {
	struct fdtable  *fdt;
	struct fdtable fdtab;
} __attribute__((preserve_access_index));

struct task_struct {
    unsigned int flags;
    const struct cred *cred;
    struct file_struct		*files;
} __attribute__((preserve_access_index));


struct linux_binprm {
	int argc;
	struct file *file;
} __attribute__((preserve_access_index));


struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 12);
} ringbuf SEC(".maps");

#define PATHLEN 256
#define MAXFILESIZE 0x20000000
#define MAY_WRITE 0x00000002
#define MAY_READ 0x00000004
/*
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 12);
} ringbuf SEC(".maps");

struct output {
	__u32 pid;
	__u32 read_write; // 0: read, 1: write
	__u64 bytes;
	char buf[PATHLEN];
};
*/
static int strcmp_64(char *s1, char *s2){
    int i;
    #pragma clang loop unroll(full)
    for(i=63;i>0;i--){
        if(s1[i] != s2[i])
            break;
    }
    return i;
}
char LICENSE[] SEC("license") = "GPL";

int my_pid = 0;
char * my_filename = NULL;


SEC("lsm/bprm_check_security")
int BPF_PROG(handler_bprm_check, struct linux_binprm *bprm)
{
        int pid = bpf_get_current_pid_tgid() >> 32;

       // if (pid != my_pid)
        //        return 0;
	
       bpf_printk("bprm_check  triggered from PID %d.\n", pid);

        bpf_printk("bprm_check  triggered from PID %s.\n", bprm->file->f_path.dentry->d_name.name);
        if (bprm->argc == 0) {
          //      log_process_name(bprm);
                return -EINVAL;
        }

        bpf_printk("bprm_check  triggered from PID %s.\n", bprm->file->f_path.dentry->d_name.name);
	bpf_printk("form user  %s \n",my_filename);
	
	if(strcmp_64((char *)bprm->file->f_path.dentry->d_name.name , "filename"))      //filename
	{	
	
                return -EINVAL;
	}

        return 0;
}


SEC("lsm/bprm_creds_from_file")
int BPF_PROG(handler_bprm_creds_from_file, struct linux_binprm *bprm, struct file *file)
{

	return 0;
}

/*
SEC("lsm/file_open")
int BPF_PROG(handle_file_open, struct file *now, int ret)
{

    	struct task_struct *task;
	struct files_struct *files = NULL;
	struct file *fd = NULL;

	struct fdtable *fdt = NULL;
        char *filename = NULL;

	const char fmt_str[] = "hello world,my pid is %d\n";
      	if (ret) {
        	return ret;
    	}
        int pid = bpf_get_current_pid_tgid() >> 32;

        if (pid != my_pid)
                return 0;

        bpf_printk("file_open  triggered from PID %d.\n", pid);


//  char msg[] = "Hello, BPF World!";
//  bpf_trace_printk(msg, sizeof(msg));
//        task = bpf_get_current_task_btf();
//	files = task->files;
//	fdt = files->fdt;

//	fd = fdt->fd;

	//filename = fd->f_path.dentry->d_iname;
	
//	filename = now->f_path.dentry->d_iname;
//	bpf_trace_printk(fmt_str, sizeof(fmt_str), pid);
//	bpf_trace_printk(filename,sizeof(filename),pid);
//	bpf_printk("%s", &filename);
//	if(strcmp_64((char *)filename , "passwd") )
//        {
//                return -EPERM;
//        }
	if(now->f_flags)
	{
		return -EPERM;
	}

	return 0;
}
*/

SEC("lsm/cred_prepare")
int BPF_PROG(handle_cred_prepare, struct cred *new, const struct cred *old,
             gfp_t gfp, int ret)
{
    struct pt_regs *regs;
    struct task_struct *task;
    kernel_cap_t caps;
    int syscall;
    unsigned long flags;
    
    // If previous hooks already denied, go ahead and deny this one
    if (ret) {
        return ret;
    }

    task = bpf_get_current_task_btf();
    regs = (struct pt_regs *) bpf_task_pt_regs(task);
    // In x86_64 orig_ax has the syscall interrupt stored here
    syscall = regs->orig_ax;
    caps = task->cred->cap_effective;

    if (caps.cap[CAP_TO_INDEX(CAP_SYS_ADMIN)] & CAP_TO_MASK(CAP_SYS_ADMIN)) {
        return -EPERM;
    }

    //deny the active for cap up
    if(&new->cap_effective == &old->cap_effective){
    
    return -EPERM;
    }

    return 0;
}


