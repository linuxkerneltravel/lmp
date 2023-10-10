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
// eBPF map for the new life image

#ifndef __NEWLIFE_IMAGE_H
#define __NEWLIFE_IMAGE_H

struct bind_pid{
    int pid;
    int newlife_pid;
};

struct newlife_start{
    int flag;       // 1代表fork，2代表vfork，3代表pthread_create
    long long unsigned int start;
};

struct newlife_event{
    int flag;
    int newlife_pid;
    long long unsigned int start;
    long long unsigned int exit;
};

#endif /* __CHILD_IMAGE_H */