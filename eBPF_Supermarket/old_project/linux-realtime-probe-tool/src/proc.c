#include "../include/lib.h"
#include "../include/proc.h"
#include "../include/percpu.h"
#include "../include/objpool.h"
#include "../include/kfifo.h"
#include "../include/xarray.h"
#include "../include/kprobe.h"
#include "../include/data.h"
#include "../include/workqueue.h"
#include "../include/kthread.h"

int enable_parm = 0;
int threshold_ns = 50000;
int savetime_s = 300;

char *filter_str = "- [usage]: echo [$pid] [$cpu] [$addr] > filter\n- And then cat stack_output\n";

unsigned long filter_key = 0;
unsigned long filter_address = 0;

#define node_num 6

#define node_enable "enable"
#define node_threshold "threshold"
#define node_savetime "savetime"
#define node_lock_info "lock_info"
#define node_filter "filter"
#define node_stack_output "stack_output"

char kstring[32];

struct proc_dir_entry *root;

struct proc_dir_entry *node[node_num];
const char *nodeName[node_num] = {
	node_enable,
	node_threshold,
	node_savetime,
	node_lock_info,
	node_filter,
	node_stack_output
	};

extern int getNodeParm(int mode)
{
	if (mode == enable)
		return enable_parm;
	else if (mode == threshold)
		return threshold_ns;
	else if (mode == savetime)
		return savetime_s;
	else
		return -1;
}

// enable ops-func
static ssize_t enable_read(struct file *file, char __user *buf, size_t lbuf, loff_t *ppos)
{
	int nbytes = sprintf(kstring, "%d\n", enable_parm);
	return simple_read_from_buffer(buf, lbuf, ppos, kstring, nbytes);
}

static ssize_t enable_write(struct file *file, const char __user *buf, size_t lbuf, loff_t *ppos)
{
	ssize_t rc;
	int oldparm, newparm;

	oldparm = enable_parm;
	rc = simple_write_to_buffer(kstring, lbuf, ppos, buf, lbuf);
	sscanf(kstring, "%d", &newparm);

	if (checkParm(oldparm, newparm, enable) != 0)
		return -EIO;
	return rc;
}

// threshold ops-func
static ssize_t threshold_read(struct file *file, char __user *buf, size_t lbuf, loff_t *ppos)
{
	int nbytes = sprintf(kstring, "%d\n", threshold_ns);
	return simple_read_from_buffer(buf, lbuf, ppos, kstring, nbytes);
}

static ssize_t threshold_write(struct file *file, const char __user *buf, size_t lbuf, loff_t *ppos)
{
	ssize_t rc;
	int oldparm, newparm;

	oldparm = threshold_ns;
	rc = simple_write_to_buffer(kstring, lbuf, ppos, buf, lbuf);
	sscanf(kstring, "%d", &newparm);

	if (checkParm(oldparm, newparm, threshold) != 0)
		return -EIO;
	return rc;
}

// savetime ops-func
static ssize_t savetime_read(struct file *file, char __user *buf, size_t lbuf, loff_t *ppos)
{
	int nbytes = sprintf(kstring, "%d\n", savetime_s);
	return simple_read_from_buffer(buf, lbuf, ppos, kstring, nbytes);
}

static ssize_t savetime_write(struct file *file, const char __user *buf, size_t lbuf, loff_t *ppos)
{
	ssize_t rc;
	int oldparm, newparm;

	oldparm = savetime_s;
	rc = simple_write_to_buffer(kstring, lbuf, ppos, buf, lbuf);

	sscanf(kstring, "%d", &newparm);

	if (checkParm(oldparm, newparm, savetime) != 0)
		return -EIO;
	return rc;
}

static int lock_info_print(struct seq_file *p, void *v)
{
	unsigned long index;
	int file_index;
	struct task_info *task_info;
	struct file_node *file_node;
	struct lock_info *lock_info;
	const char *fmt_null = "null";

	rcu_read_lock();
	xa_for_each(xa, index, task_info)
	{
		seq_printf(p, "Lock Info:\npid: %-6u cpu: %-4u comm: %-16s exe: %-s\n", task_info->pid, task_info->cpu, task_info->comm, task_info->exe);

		down_read(&(task_info->sem));

		if (!list_empty(&(task_info->files.head)))
		{
			seq_printf(p, "Files:\n");
			file_index = 0;
			list_for_each_entry(file_node, &(task_info->files.head), node)
			{
				if (strcmp(fmt_null, file_node->file_name))
				{
					seq_printf(p, "[%02d] - %s\n",file_index ,file_node->file_name);
					file_index++;
				}
			}
		}

		spin_lock_irq(&(task_info->locks.lock));
		seq_printf(p, "Locks:\ntotal_nums:%u  total_times:%lu\n", task_info->locks.total_num, task_info->locks.total_time);

		list_for_each_entry(lock_info, &(task_info->locks.head), node)
		{
			seq_printf(p, "addr:%lx \t t1:%ld \t nums:%u \t times:%lu\n",
					   lock_info->lock_addr, lock_info->lock_time_stamp, lock_info->lock_num, lock_info->lock_time);
		}
		spin_unlock_irq(&(task_info->locks.lock));

		up_read(&(task_info->sem));
		seq_printf(p, "-------------------------------------------------\n\n");
	}
	rcu_read_unlock();
	return 0;
}

static int lock_info_open(struct inode *inode, struct file *file)
{
	unsigned int size = PAGE_SIZE;

	return single_open_size(file, lock_info_print, NULL, size);
}

// filter_ops
static int filter_print(struct seq_file *p, void *v)
{
	seq_puts(p,filter_str);
	return 0;
}

static int filter_open(struct inode *inode, struct file *file)
{
	unsigned int size = PAGE_SIZE;
	return single_open_size(file, filter_print, NULL, size);
}

static ssize_t filter_write(struct file *filter, const char __user *buf, size_t lbuf, loff_t *ppos)
{
	ssize_t rc;
	unsigned long pid, cpu;
	unsigned long address, key;

	rc = simple_write_to_buffer(kstring, lbuf, ppos, buf, lbuf);
	sscanf(kstring, "%ld %ld %lx", &pid, &cpu, &address);

	if (pid < 0 || cpu < 0)
	{
		return -EIO;
	}

	if (!pid)
	{
		key = (cpu << 32) | pid;
	}
	else
	{
		key = pid;
	}

	filter_address = address;
	filter_key = key;

	return rc;
}

// stack_output pos
static int stack_output_print(struct seq_file *p, void *v)
{
	int find = 0;
	int i;
	unsigned long index = filter_key;
	unsigned long address = filter_address;

	struct task_info *task_info;
	struct lock_info *lock_info;

	task_info = xa_load(xa, filter_key);
	if (task_info == NULL)
	{
		seq_printf(p, "not found!");
	}
	else
	{
		seq_printf(p, "pid: %-6u cpu: %-4u comm: %-16s exe: %-s\n",
				   task_info->pid, task_info->cpu, task_info->comm, task_info->exe);

		down_read(&(task_info->sem));
		spin_lock_irq(&(task_info->locks.lock));

		list_for_each_entry(lock_info, &(task_info->locks.head), node)
		{
			if (lock_info->lock_addr == filter_address)
			{
				find = 1;
				seq_printf(p, "Call Trace:\n");
				for (i = 0; i < lock_info->num_entries; i++)
				{
					seq_printf(p, "[%02d]-[%p] %pS\n", i, (void *)lock_info->stack_entries[i], (void *)lock_info->stack_entries[i]);
				}

				break;
			}
		}

		spin_unlock_irq(&(task_info->locks.lock));
		up_read(&(task_info->sem));

		if (!find)
		{
			seq_printf(p, "not found!\n");
		}
	}

	return 0;
}

static int stack_output_open(struct inode *inode, struct file *file)
{
	unsigned int size = PAGE_SIZE;

	return single_open_size(file, stack_output_print, NULL, size);
}

// all ops-func
struct proc_ops fops[node_num] = {
	{
		.proc_read = enable_read,
		.proc_write = enable_write,
	},
	{.proc_read = threshold_read,
	 .proc_write = threshold_write},
	{.proc_read = savetime_read,
	 .proc_write = savetime_write},
	{
		.proc_flags = PROC_ENTRY_PERMANENT,
		.proc_open = lock_info_open,
		.proc_read_iter = seq_read_iter,
		.proc_lseek = seq_lseek,
		.proc_release = single_release,
	},
	{
		.proc_flags = PROC_ENTRY_PERMANENT,
		.proc_open = filter_open,
		.proc_read_iter = seq_read_iter,
		.proc_lseek = seq_lseek,
		.proc_release = single_release,
		.proc_write = filter_write,
	},
	{
		.proc_flags = PROC_ENTRY_PERMANENT,
		.proc_open = stack_output_open,
		.proc_read_iter = seq_read_iter,
		.proc_lseek = seq_lseek,
		.proc_release = single_release,
	}};

// create root
extern void root_init(void)
{
	root = proc_mkdir("irq_time_info", NULL);
	if (IS_ERR(root))
	{
		pr_err("Failed to create node root!\n");
	}
	if(DEBUG)
		printk(KERN_INFO "Successfully created node root!\n");
}

extern void root_exit(void)
{
	proc_remove(root);
	if(DEBUG)
		printk(KERN_INFO "Successfully removed node-root\n");
}

// create other node
extern int node_init()
{
	int nodeIndex;

	for (nodeIndex = 0; nodeIndex < node_num; nodeIndex++)
	{
		node[nodeIndex] = proc_create(nodeName[nodeIndex], 0, root, &(fops[nodeIndex]));
		if (IS_ERR(node))
		{
			printk(KERN_ERR "Failed to create node %d %s\n", nodeIndex, nodeName[nodeIndex]);
			return -1;
		}
		if(DEBUG)
			printk(KERN_INFO "Successfully created node %d %s\n", nodeIndex, nodeName[nodeIndex]);
	}

	return 0;
}

extern void node_exit(void)
{
	int nodeIndex;
	for (nodeIndex = 0; nodeIndex < node_num; nodeIndex++)
	{
		if (node[nodeIndex])
		{
			proc_remove(node[nodeIndex]);
			if(DEBUG)
				printk(KERN_INFO "Successfully removed node-%s\n", nodeName[nodeIndex]);
		}
	}
}

extern int checkParm(int oldParm, int newParm, int mode)
{
	switch (mode)
	{
	case enable: // enable
		if (newParm > 1 || newParm < 0)
		{
			return -1;
		}
		else if (newParm != oldParm)
		{
			changeEnableStatus(newParm);
		}
		break;
	case threshold: // threshold
		if (newParm < 0)
		{
			return -1;
		}
		else
		{
			threshold_ns = newParm;
			return 0;
		}
		break;
	case savetime: // savetime
		if (newParm < 0)
		{
			return -1;
		}
		else
		{
			savetime_s = newParm;
			return 0;
		}
		break;
	default:
		return -1;
		break;
	}
	return 0;
	;
}

extern void changeEnableStatus(int status)
{
	if (status == ON)
	{
		enable_parm = 1;
		printk("Kernel Module Irq_mod Is Start\n");//打开
		// 1. percpu变量
		// 2. 对象池
		// 3. kfifo
		// 4. xa
		// 5. workqueue
		// 6. 注册kprobe
		alloc_percpu_lock_entry();
		alloc_kp_pool();
		fifo_init();
		alloc_xarray();
		// wq_init();
		datasave_task_init();
		// spin_lock_irq_init();
		spin_lock_irqsave_init();
	}
	else if (status == OFF)
	{
		enable_parm = 0;
		printk("Kernel Module Irq_mod Is Stop\n");//关闭
		spin_lock_irqsave_exit();
		// spin_lock_irq_exit();
		datasave_task_exit();
		msleep(20);
		destroy_xarray();
		fifo_exit();
		destroy_kp_pool();
		free_percpu_lock_entry();
	}
}

MODULE_LICENSE("GPL");
