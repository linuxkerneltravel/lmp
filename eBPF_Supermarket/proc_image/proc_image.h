#ifndef __PROC_IMAGE_H
#define __PROC_IMAGE_H

#define TASK_COMM_LEN 16

struct sleep_offcpu{
    int pad;
    int offcpu_id;
    long long unsigned int offcpu_time;
};

struct sleep_event{
    int pid;
    char comm[TASK_COMM_LEN];
    int offcpu_id;
    long long unsigned int offcpu_time;
    int oncpu_id;
    long long unsigned int oncpu_time;
};



#endif /* __PROC_IMAGE_H */