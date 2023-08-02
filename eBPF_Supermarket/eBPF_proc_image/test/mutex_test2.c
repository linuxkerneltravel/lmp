#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/mutex.h>
#include <linux/delay.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/fs_struct.h>
#include <linux/kthread.h>

MODULE_LICENSE("GPL");

static struct mutex mutex1;
static struct mutex mutex2;

static int test_init(void) {
    pid_t pid = current->pid;
    
    mutex_init(&mutex1);
    mutex_init(&mutex2);

    printk(KERN_INFO "Hello from kernel module. PID: %d\n", pid);

    ssleep(20);
    mutex_lock(&mutex1);
    ssleep(3);
    mutex_lock(&mutex2);
    mutex_unlock(&mutex1);
    ssleep(6);
    mutex_unlock(&mutex2);

    return 0;
}

static void test_exit(void) {
    printk(KERN_INFO "Goodbye from kernel module\n");
}

module_init(test_init);
module_exit(test_exit);