#include "../include/lib.h"
#include "../include/kprobe.h"
#include "../include/proc.h"
#include "../include/data.h"

extern void init_task_info(struct task_info *task_info, struct kp_info *kp_info)
{
    int kthread;
    struct task_struct *task;
    struct qstr *d_name;
    struct file *exe;
    const char *fmt_null = "Null";

    if (DEBUG)
        printk(KERN_INFO "init_task_info get_task\n");

    task = kp_info->task;
    kthread = (task->mm == NULL) ? 1 : 0; //区分线程

    if (!kthread)
    {
        rcu_read_lock();
        exe = rcu_dereference_raw(task->mm->exe_file);

        if (exe)
        {
            d_name = &(exe->f_path.dentry->d_name);
            strncpy(task_info->exe, d_name->name, MAX_FILE_LEN);
        }
        else
        {
            strncpy(task_info->exe, fmt_null, MAX_FILE_LEN);
        }
        rcu_read_unlock();
    }
    else
    {
        strncpy(task_info->exe, fmt_null, MAX_FILE_LEN);
    }

    task_info->pid = task->pid;
    task_info->cpu = kp_info->cpu;

    memcpy(task_info->comm, task->comm, TASK_COMM_LEN);

    init_rwsem(&(task_info->sem));

    task_info->files.open_fds = 0;
    INIT_LIST_HEAD(&(task_info->files.head));

    task_info->locks.total_num = 0;
    task_info->locks.total_time = 0;
    INIT_LIST_HEAD(&(task_info->locks.head));
    spin_lock_init(&(task_info->locks.lock));
}

/*非活跃锁处理*/
static void timer_handler(struct timer_list *timer)
{
    struct lock_info *lock_info;
    lock_info = container_of(timer, struct lock_info, timer);

    spin_lock(&(lock_info->lock_list->lock));

    lock_info->lock_list->total_num -= lock_info->lock_num;
    lock_info->lock_list->total_time -= lock_info->lock_time;
    list_del(&(lock_info->node));

    spin_unlock(&(lock_info->lock_list->lock));

    kfree(lock_info);
    lock_info = NULL;
}

extern void update_task_info(struct task_info *task_info, struct kp_info *kp_info)
{
    unsigned long fds, lock_addr, delta;
    unsigned int fd_bit, fd, find;
    struct fdtable *fdt;
    struct files_struct *files;
    struct file *f;
    struct qstr *d_name;
    struct inode *f_inode;
    // struct sock *sk;
    struct file_node *file_node;
    // struct sock_private *sock_private;
    struct lock_info *lock_info;
    struct task_struct *task;

    task = kp_info->task;

    down_write(&(task_info->sem));

    rcu_read_lock();

    files = task->files;
    if (files == NULL)
        goto rcu_unlock;

    fdt = rcu_dereference_raw(task->files->fdt);
    if (fdt == NULL || fdt->open_fds == NULL)
        goto rcu_unlock;

    fds = *(fdt->open_fds);
    fds ^= task_info->files.open_fds;
    fds &= ~(task_info->files.open_fds);

    task_info->files.open_fds |= fds;

    if (fds) // tt
    {
        while ((fd_bit = ffs(fds)))
        {
            fd = fd_bit - 1;

            f = rcu_dereference_raw(fdt->fd[fd]);
            if (f)
            {
                file_node = kmalloc(sizeof(*file_node), GFP_KERNEL);
                if (DEBUG)
                    printk(KERN_INFO "file_node address: %p\n", file_node);
                INIT_LIST_HEAD(&(file_node->node));

                d_name = &(f->f_path.dentry->d_name);
                strncpy(file_node->file_name, d_name->name, MAX_FILE_LEN);

                f_inode = f->f_inode;
                if (S_ISSOCK(f_inode->i_mode))
                {
                    file_node->f_flags = IS_SOCK;
                    // sock_private = kmalloc(sizeof(*sock_private), GFP_KERNEL);

                    // sk = ((struct socket *)(f->private_data))->sk;

                    // sock_private->sk_num = sk->sk_num;
                    // sock_private->sk_dport = sk->sk_dport;
                    // sock_private->sk_daddr = sk->sk_daddr;
                    // sock_private->sk_rcv_saddr = sk->rcv_saddr;
                    // sock_private->protocol = sk->sk_protocol;

                    // file->node->private = sock_private;
                    file_node->private_data = NULL;
                }
                else
                {
                    file_node->f_flags = 0;
                    file_node->private_data = NULL;
                }
                list_add_tail(&(file_node->node), &(task_info->files.head));
            }
            fds >>= fd_bit;
        }
    }
rcu_unlock:
    rcu_read_unlock();

    lock_addr = kp_info->lock_addr;
    delta = kp_info->delta;

    find = 0;
    if (DEBUG)
        printk(KERN_INFO "Start lock list_for_each_entry find\n");
    list_for_each_entry(lock_info, &(task_info->locks.head), node)
    {
        if (lock_info->lock_addr == lock_addr)
        {
            find = 1;

            spin_lock_irq(&(task_info->locks.lock));

            lock_info->timer.expires = jiffies + HZ * getNodeParm(savetime);
            mod_timer(&(lock_info->timer), lock_info->timer.expires);
            lock_info->lock_num++;
            lock_info->lock_time += kp_info->delta;

            task_info->locks.total_num++;
            task_info->locks.total_time += delta;

            spin_unlock_irq(&(task_info->locks.lock));

            break;
        }
    }

    if (DEBUG)
        printk(KERN_INFO "Finish lock list_for_each_entry\n");
    if (!find)
    {
        lock_info = kmalloc(sizeof(*lock_info), GFP_KERNEL); // tt

        lock_info->lock_num = 1;
        lock_info->lock_time = delta;
        lock_info->lock_addr = lock_addr;
        lock_info->num_entries = kp_info->num_entries;
        lock_info->lock_time_stamp = ktime_get_ns();

        memcpy(lock_info->stack_entries, kp_info->stack_entries, sizeof(unsigned long) * NUM_STACK_ENTRIES);
        INIT_LIST_HEAD(&(lock_info->node));
        lock_info->lock_list = &(task_info->locks);
        timer_setup(&(lock_info->timer), timer_handler, 0);
        lock_info->timer.expires = jiffies + HZ * getNodeParm(savetime);

        spin_lock_irq(&(task_info->locks.lock));

        add_timer(&(lock_info->timer));
        list_add_tail(&(lock_info->node), &(task_info->locks.head));
        task_info->locks.total_num++;
        task_info->locks.total_time += delta;

        spin_unlock_irq(&(task_info->locks.lock));
    }
    up_write(&(task_info->sem));
}

extern void free_task_info(struct task_info *task_info)
{
    struct file_node *file_node, *file_node_next;
    struct lock_info *lock_info, *lock_info_next;
    struct file_list *file_list;
    struct lock_list *lock_list;
    struct sock_private *sock_private;

    down_write(&(task_info->sem));

    file_list = &(task_info->files);
    lock_list = &(task_info->locks);

    list_for_each_entry_safe(file_node, file_node_next, &(file_list->head), node)
    {
        if (file_node->private_data)
        {
            sock_private = (struct sock_private *)file_node->private_data;
            kfree(sock_private);
        }
        list_del(&(file_node->node));
        kfree(file_node);
    }

    spin_lock_irq(&(lock_list->lock));

    list_for_each_entry_safe(lock_info, lock_info_next, &(lock_list->head), node)
    {
        list_del(&(lock_info->node));
        del_timer(&(lock_info->timer));
        kfree(lock_info);
    }

    spin_unlock_irq(&(lock_list->lock));

    up_write(&(task_info->sem));

    kfree(task_info);
}

MODULE_LICENSE("GPL");
