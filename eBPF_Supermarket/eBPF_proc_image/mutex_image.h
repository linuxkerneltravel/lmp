#ifndef __MUTEX_IMAGE_H
#define __MUTEX_IMAGE_H

#define TASK_COMM_LEN 16

struct mutex_event{
    int pid;
    char comm[TASK_COMM_LEN];
    //long long unsigned int lock_ptr;
    long long unsigned int mutex_acq_time;
    long long unsigned int mutex_lock_time;
    long long unsigned int mutex_unlock_time;
};

#endif /* __MUTEX_IMAGE_H */