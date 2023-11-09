// Copyright 2023 The LMP Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// https://github.com/linuxkerneltravel/lmp/blob/develop/LICENSE
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// author: zhangziheng0525@163.com
//
// process mutex image test program for case 1

#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/mutex.h>
#include <linux/delay.h>

MODULE_LICENSE("GPL");

static struct mutex mutex;

static int test_init(void) {
    pid_t pid = current->pid;

    mutex_init(&mutex);
    
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
