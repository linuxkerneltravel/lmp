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
// eBPF map for the process mutex image

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