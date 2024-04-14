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
// Variable definitions and help functions for lock in the process

static int record_lock_enter(pid_t ignore_tgid,int lock_status,int flag,void *__lock,void *lock_rb,void *proc_lock,void *lock_ctrl_map)
{
    int key = 0;
    struct lock_ctrl *lock_ctrl;
    lock_ctrl = bpf_map_lookup_elem(lock_ctrl_map,&key);
    if(!lock_ctrl || !lock_ctrl->lock_func)
		return 0;
    
    pid_t pid = bpf_get_current_pid_tgid();
    int tgid = bpf_get_current_pid_tgid() >> 32;

    if((lock_ctrl->enable_myproc || tgid!=ignore_tgid) && ((lock_ctrl->target_pid==-1 && lock_ctrl->target_tgid==-1) || 
       (lock_ctrl->target_pid!=0 && pid==lock_ctrl->target_pid) || (lock_ctrl->target_tgid!=0 && tgid==lock_ctrl->target_tgid))){
        u64 lock_ptr = (u64)__lock;
        struct proc_flag proc_flag = {};
        
        proc_flag.pid = pid;
        proc_flag.flag = flag;
        if(bpf_map_update_elem(proc_lock, &proc_flag, &lock_ptr, BPF_ANY))
            return 0;

        struct lock_event* e;
        e = bpf_ringbuf_reserve(lock_rb, sizeof(*e), 0);
        if(!e)
            return 0;

        e->lock_status = lock_status;
        e->pid = pid;
        if(lock_ctrl->target_tgid != -1)	e->tgid = tgid;
        else	e->tgid = -1;
        e->lock_ptr = lock_ptr;
        e->time = bpf_ktime_get_ns();
        
        bpf_ringbuf_submit(e, 0);
    }

    return 0;
}

static int record_lock_exit(pid_t ignore_tgid,int lock_status,int flag,int ret,void *lock_rb,void *proc_lock,void *locktype,void *lock_ctrl_map)
{
    int key = 0;
    struct lock_ctrl *lock_ctrl;
    lock_ctrl = bpf_map_lookup_elem(lock_ctrl_map,&key);
    if(!lock_ctrl || !lock_ctrl->lock_func)
		return 0;
    
    pid_t pid = bpf_get_current_pid_tgid();
    int tgid = bpf_get_current_pid_tgid() >> 32;

    if((lock_ctrl->enable_myproc || tgid!=ignore_tgid) && ((lock_ctrl->target_pid==-1 && lock_ctrl->target_tgid==-1) || 
       (lock_ctrl->target_pid!=0 && pid==lock_ctrl->target_pid) || (lock_ctrl->target_tgid!=0 && tgid==lock_ctrl->target_tgid))){
        u64 *lock_ptr;
        u64 temp_lock_ptr;
        struct proc_flag proc_flag = {};

        proc_flag.pid = pid;
        proc_flag.flag = flag;

        lock_ptr = bpf_map_lookup_elem(proc_lock, &proc_flag);
        if(!lock_ptr)
            return 0;
        temp_lock_ptr = *lock_ptr;
        bpf_map_delete_elem(proc_lock, &proc_flag);

        if((lock_status==5 || lock_status==8) && ret==0){
            int type;

            if(lock_status == 5)  type= 1;
            else    type= 2;

            if(bpf_map_update_elem(locktype, &temp_lock_ptr, &type, BPF_ANY))
                return 0;
        }

        struct lock_event* e;
        e = bpf_ringbuf_reserve(lock_rb, sizeof(*e), 0);
        if(!e)
            return 0;

        e->lock_status = lock_status;
        e->pid = pid;
        if(lock_ctrl->target_tgid != -1)	e->tgid = tgid;
        else	e->tgid = -1;
        e->ret = ret;
        e->lock_ptr = temp_lock_ptr;
        e->time = bpf_ktime_get_ns();
        
        bpf_ringbuf_submit(e, 0);
    }

    return 0;
}

static int record_unlock_enter(pid_t ignore_tgid,int flag,void *__lock,void *proc_unlock,void *lock_ctrl_map)
{
    int key = 0;
    struct lock_ctrl *lock_ctrl;
    lock_ctrl = bpf_map_lookup_elem(lock_ctrl_map,&key);
    if(!lock_ctrl || !lock_ctrl->lock_func)
		return 0;
    
    pid_t pid = bpf_get_current_pid_tgid();
    int tgid = bpf_get_current_pid_tgid() >> 32;

    if((lock_ctrl->enable_myproc || tgid!=ignore_tgid) && ((lock_ctrl->target_pid==-1 && lock_ctrl->target_tgid==-1) || 
       (lock_ctrl->target_pid!=0 && pid==lock_ctrl->target_pid) || (lock_ctrl->target_tgid!=0 && tgid==lock_ctrl->target_tgid))){
        u64 lock_ptr = (u64)__lock;
        struct proc_flag proc_flag = {};

        proc_flag.pid = pid;
        proc_flag.flag = flag;

        bpf_map_update_elem(proc_unlock, &proc_flag, &lock_ptr, BPF_ANY);
    }

    return 0;
}

static int record_unlock_exit(pid_t ignore_tgid,int lock_status,int flag,void *lock_rb,void *proc_unlock,void *locktype,void *lock_ctrl_map)
{
    int key = 0;
    struct lock_ctrl *lock_ctrl;
    lock_ctrl = bpf_map_lookup_elem(lock_ctrl_map,&key);
    if(!lock_ctrl || !lock_ctrl->lock_func)
		return 0;
    
    pid_t pid = bpf_get_current_pid_tgid();
    int tgid = bpf_get_current_pid_tgid() >> 32;

    if((lock_ctrl->enable_myproc || tgid!=ignore_tgid) && ((lock_ctrl->target_pid==-1 && lock_ctrl->target_tgid==-1) || 
       (lock_ctrl->target_pid!=0 && pid==lock_ctrl->target_pid) || (lock_ctrl->target_tgid!=0 && tgid==lock_ctrl->target_tgid))){
        u64 *lock_ptr;
        u64 temp_lock_ptr;
        struct proc_flag proc_flag = {};

        proc_flag.pid = pid;
        proc_flag.flag = flag;
        
        lock_ptr = bpf_map_lookup_elem(proc_unlock, &proc_flag);
        if(!lock_ptr)
            return 0;
        temp_lock_ptr = *lock_ptr;
        bpf_map_delete_elem(proc_unlock, &proc_flag);

        if(lock_status ==0){
            int *type;

            type = bpf_map_lookup_elem(locktype, &temp_lock_ptr);
            if(!type)
                return 0;
            
            if(*type == 1)  lock_status = 6;
            else if(*type == 2) lock_status = 9;
            bpf_map_delete_elem(locktype, &temp_lock_ptr);
        }
        
        struct lock_event* e;
        e = bpf_ringbuf_reserve(lock_rb, sizeof(*e), 0);
        if(!e)
            return 0;
        
        e->lock_status = lock_status;
        e->pid = pid;
        if(lock_ctrl->target_tgid != -1)	e->tgid = tgid;
        else	e->tgid = -1;
        e->lock_ptr = temp_lock_ptr;
        e->time = bpf_ktime_get_ns();
        
        bpf_ringbuf_submit(e, 0);
    }

    return 0;
}