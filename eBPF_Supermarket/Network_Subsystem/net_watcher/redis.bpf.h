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
// author: blown.away@qq.com
// mysql

#include "common.bpf.h"
#include "redis_helper.bpf.h"

static __always_inline int __handle_redis_start(struct pt_regs *ctx) {
    struct client *cli = (struct client *)PT_REGS_PARM1(ctx);
    int argc;               
    char name; 
    int argv_len;          
    bpf_probe_read(&argc, sizeof(argc), &cli->argc);
    robj **arg0;
    robj *arg1;
    //unsigned type;
    unsigned encoding;
    unsigned lru; 
    int refcount;
    bpf_probe_read(&arg0, sizeof(arg0), &cli->argv);

    // 读取 argv[0]，即第一个命令参数
    bpf_probe_read(&arg1, sizeof(arg1), &arg0[1]);

    // 读取 argv[0]->ptr 中的字符串
    bpf_probe_read(&name, sizeof(name),&arg1->ptr);
    bpf_probe_read(&argv_len, sizeof(argv_len), &cli->argv_len_sum);
;
    bpf_printk("%d %s %d",argc,name,argv_len);

    pid_t pid = bpf_get_current_pid_tgid() >> 32;
    return 0;
}

