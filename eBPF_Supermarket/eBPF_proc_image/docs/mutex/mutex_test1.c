#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/mutex.h>
#include <linux/delay.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/fs_struct.h>

MODULE_LICENSE("GPL");

static struct mutex mutex;

static int test_init(void) {
    pid_t pid = current->pid;
    printk(KERN_INFO "Hello from kernel module. PID: %d\n", pid);

    ssleep(15);                 //为了在持有锁之前读取进程pid，以便对其进行跟踪

    mutex_lock(&mutex);
    ssleep(3); 
    mutex_unlock(&mutex);

    return 0;
}

static void test_exit(void) {
    printk(KERN_INFO "Goodbye from kernel module\n");
}

module_init(test_init);
module_exit(test_exit);
