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
// eBPF map for the process lock image

#ifndef __LOCK_IMAGE_H
#define __LOCK_IMAGE_H

#define TASK_COMM_LEN 16

struct proc_lockptr{
    int pid;
    long long unsigned int lock_ptr;
};

struct lock_event{
    int type;       // 1代表用户态互斥锁；2代表内核态互斥锁；3代表用户态读模式下的读写锁；4代表用户态写模式下的读写锁
    int pid;
    char comm[TASK_COMM_LEN];
    long long unsigned int lock_ptr;
    long long unsigned int lock_acq_time;
    long long unsigned int lock_time;
    long long unsigned int unlock_time;
};

#endif /* __LOCK_IMAGE_H */