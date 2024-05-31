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

#include "common.bpf.h"
static __always_inline
int __handle_mysql_start(struct pt_regs *ctx)
{
    //dispatch_command(THD *thd, const COM_DATA *com_data, enum enum_server_command command)
    char comm[16];
    //struct mysql_query data = {};
    enum  enum_server_command command = PT_REGS_PARM3(ctx);
    union COM_DATA  *com_data = (union COM_DATA *)PT_REGS_PARM2(ctx);
    
    pid_t pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&comm, sizeof(comm));
    void *thd = (void *)PT_REGS_PARM1(ctx);
    char *sql;  
    u32 size = 0;
    if(command != COM_QUERY)
    {
        return 0;
    }
    bpf_probe_read(&size, sizeof(size), &com_data->com_query.length);
    bpf_probe_read_str(&sql, sizeof(sql), &com_data->com_query.query);
    bpf_printk("pid======%d,comm========%s,size=======%u,sql=========%s", pid,comm,size,sql);
    return 0;
}
