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
// Variable definitions and help functions for keytime in the process

// 记录开始时间，并输出
static int child_create(int type, pid_t child_pid, pid_t pid, void *child, void *keytime_rb, int tgid, int target_tgid)
{
	struct child_info child_info = {};
    child_info.type = type;
    child_info.ppid = pid;
    if(target_tgid != -1)   child_info.ptgid = tgid;
    else    child_info.ptgid = -1;
    if(bpf_map_update_elem(child, &child_pid, &child_info, BPF_ANY))
        return 0;
    
    struct keytime_event* e;
    e = bpf_ringbuf_reserve(keytime_rb, sizeof(*e), 0);
    if(!e)
        return 0;

    e->type = type;
    e->pid = pid;
    if(target_tgid != -1)	e->tgid = tgid;
	else	e->tgid = -1;
    e->enable_char_info = false;
    e->info_count = 1;
    e->info[0] = child_pid;

    bpf_ringbuf_submit(e, 0);

    return 0;
}

// 记录退出时间，并输出
static int child_exit(void *child, void *keytime_rb)
{
	pid_t child_pid = bpf_get_current_pid_tgid();
    struct child_info *child_info = bpf_map_lookup_elem(child, &child_pid);
    if(child_info){
        struct keytime_event* e;
        e = bpf_ringbuf_reserve(keytime_rb, sizeof(*e), 0);
        if(!e)
            return 0;

        e->type = child_info->type + 1;
        e->pid = child_info->ppid;
        e->tgid = child_info->ptgid;
        e->enable_char_info = false;
        e->info_count = 1;
        e->info[0] = child_pid;

        bpf_ringbuf_submit(e, 0);
        bpf_map_delete_elem(child,&child_pid);
    }

	return 0;
}