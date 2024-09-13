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
// author: albert_xuu@163.com zhangxy1016304@163.com zhangziheng0525@163.com
#ifndef CPU_WATCHER_HELPER_H
#define CPU_WATCHER_HELPER_H

#include <stdio.h>
#include "cpu_watcher.h"

#define SAR_WACTHER 10
#define CS_WACTHER 20
#define SC_WACTHER 30
#define PREEMPT_WACTHER 40
#define SCHEDULE_WACTHER 50
#define MQ_WACTHER 60
#define MUTEX_WATCHER 70
#define HASH_SIZE 1024

/*----------------------------------------------*/
/*          ewma算法                            */
/*----------------------------------------------*/
//滑动窗口周期，用于计算alpha
#define CYCLE 10
//阈值容错空间；
#define TOLERANCE 1.0
struct ewma_info{
	double previousEWMA;
	int count;
	int cycle;//cycle是滑动窗口周期大小
};

double calculateEWMA(double previousEWMA, double dataPoint, double alpha) {
    return alpha * dataPoint + (1 - alpha) * previousEWMA;//当前时间点的ewma
}

bool dynamic_filter(struct ewma_info *ewma_syscall_delay, double dataPoint) {
    double alpha,threshold;
	if(ewma_syscall_delay->cycle==0) alpha = 2.0 /(CYCLE + 1); // 计算 alpha
	else alpha = 2.0 /(ewma_syscall_delay->cycle + 1); 

	if(ewma_syscall_delay->previousEWMA == 0) {//初始化ewma算法，则赋值previousEWMA = dataPoint 并打印
		ewma_syscall_delay->previousEWMA = dataPoint;
		return 1;
	}
	if(ewma_syscall_delay->count <30){
		ewma_syscall_delay->previousEWMA = calculateEWMA(ewma_syscall_delay->previousEWMA,dataPoint,alpha);//计算
		return 1;
	}
	else{
		ewma_syscall_delay->previousEWMA = calculateEWMA(ewma_syscall_delay->previousEWMA,dataPoint,alpha);//计算
		threshold = ewma_syscall_delay->previousEWMA * TOLERANCE;
		if(dataPoint >= threshold) return 1;
	}
    return 0;
}

/*----------------------------------------------*/
/*              bpf file system                 */
/*----------------------------------------------*/
const char *sar_ctrl_path =  "/sys/fs/bpf/cpu_watcher_map/sar_ctrl_map";
const char *cs_ctrl_path =  "/sys/fs/bpf/cpu_watcher_map/cs_ctrl_map";
const char *sc_ctrl_path =  "/sys/fs/bpf/cpu_watcher_map/sc_ctrl_map";
const char *preempt_ctrl_path =  "/sys/fs/bpf/cpu_watcher_map/preempt_ctrl_map";
const char *schedule_ctrl_path =  "/sys/fs/bpf/cpu_watcher_map/schedule_ctrl_map";
const char *mq_ctrl_path =  "/sys/fs/bpf/cpu_watcher_map/mq_ctrl_map";
const char *mu_ctrl_path =  "/sys/fs/bpf/cpu_watcher_map/mu_ctrl_map";

int common_pin_map(struct bpf_map **bpf_map, const struct bpf_object *obj, const char *map_name, const char *ctrl_path)
{
    int ret;
    
    *bpf_map = bpf_object__find_map_by_name(obj, map_name);//查找具有指定名称的 BPF 映射
    if (!*bpf_map) {
        fprintf(stderr, "Failed to find BPF map\n");
        return -1;
    }
    // 用于防止上次没有成功 unpin 掉这个 map
    bpf_map__unpin(*bpf_map, ctrl_path);
    ret = bpf_map__pin(*bpf_map, ctrl_path);
    if (ret){
        fprintf(stderr, "Failed to pin BPF map\n");
        return -1;
    }//找到pin上
	
    return 0;
}

int update_sar_ctrl_map(struct sar_ctrl sar_ctrl){
	int err,key = 0;
	int srcmap_fd;
	
	srcmap_fd = bpf_obj_get(sar_ctrl_path);
    if (srcmap_fd < 0) {
        fprintf(stderr,"Failed to open sar_ctrl_map file\n");
        return srcmap_fd;
    }
    err = bpf_map_update_elem(srcmap_fd,&key,&sar_ctrl, 0);
    if(err < 0){
        fprintf(stderr, "Failed to update sar_ctrl_map elem\n");
        return err;
    }

    return 0;
}

int update_cs_ctrl_map(struct cs_ctrl cs_ctrl){
	int err,key = 0;
	int srcmap_fd;
	
	srcmap_fd = bpf_obj_get(cs_ctrl_path);
    if (srcmap_fd < 0) {
        fprintf(stderr,"Failed to open cs_ctrl_map file\n");
        return srcmap_fd;
    }
    err = bpf_map_update_elem(srcmap_fd,&key,&cs_ctrl, 0);
    if(err < 0){
        fprintf(stderr, "Failed to update cs_ctrl_map elem\n");
        return err;
    }

    return 0;
}

int update_sc_ctrl_map(struct sc_ctrl sc_ctrl){
	int err,key = 0;
	int srcmap_fd;
	
	srcmap_fd = bpf_obj_get(sc_ctrl_path);
    if (srcmap_fd < 0) {
        fprintf(stderr,"Failed to open sc_ctrl_map file\n");
        return srcmap_fd;
    }
    err = bpf_map_update_elem(srcmap_fd,&key,&sc_ctrl, 0);
    if(err < 0){
        fprintf(stderr, "Failed to update sc_ctrl_map elem\n");
        return err;
    }

    return 0;
}

int update_preempt_ctrl_map(struct preempt_ctrl preempt_ctrl){
	int err,key = 0;
	int srcmap_fd;
	
	srcmap_fd = bpf_obj_get(preempt_ctrl_path);
    if (srcmap_fd < 0) {
        fprintf(stderr,"Failed to open preempt_ctrl_map file\n");
        return srcmap_fd;
    }
    err = bpf_map_update_elem(srcmap_fd,&key,&preempt_ctrl, 0);
    if(err < 0){
        fprintf(stderr, "Failed to update preempt_ctrl_map elem\n");
        return err;
    }

    return 0;
}

int update_schedule_ctrl_map(struct schedule_ctrl schedule_ctrl){
	int err,key = 0;
	int srcmap_fd;
	
	srcmap_fd = bpf_obj_get(schedule_ctrl_path);
    if (srcmap_fd < 0) {
        fprintf(stderr,"Failed to open schedule_ctrl_map file\n");
        return srcmap_fd;
    }
    err = bpf_map_update_elem(srcmap_fd,&key,&schedule_ctrl, 0);
    if(err < 0){
        fprintf(stderr, "Failed to update schedule_ctrl_map elem\n");
        return err;
    }

    return 0;
}

int update_mq_ctrl_map(struct mq_ctrl mq_ctrl){
	int err,key = 0;
	int srcmap_fd;
	
	srcmap_fd = bpf_obj_get(mq_ctrl_path);
    if (srcmap_fd < 0) {
        fprintf(stderr,"Failed to open mq_ctrl_map file\n");
        return srcmap_fd;
    }
    err = bpf_map_update_elem(srcmap_fd,&key,&mq_ctrl, 0);
    if(err < 0){
        fprintf(stderr, "Failed to update mq_ctrl_map elem\n");
        return err;
    }

    return 0;
}

int update_mu_ctrl_map(struct mu_ctrl mu_ctrl){
	int err,key = 0;
	int srcmap_fd;
	
	srcmap_fd = bpf_obj_get(mu_ctrl_path);
    if (srcmap_fd < 0) {
        fprintf(stderr,"Failed to open mq_ctrl_map file\n");
        return srcmap_fd;
    }
    err = bpf_map_update_elem(srcmap_fd,&key,&mu_ctrl, 0);
    if(err < 0){
        fprintf(stderr, "Failed to update mq_ctrl_map elem\n");
        return err;
    }

    return 0;
}
/*----------------------------------------------*/
/*              mutex_count                     */
/*----------------------------------------------*/

typedef struct {
    uint64_t ptr;
    uint64_t count;
} lock_count_t;

lock_count_t lock_counts[HASH_SIZE];

static uint64_t hash(uint64_t ptr) {
    return ptr % HASH_SIZE;
}

static void increment_lock_count(uint64_t ptr) {
    uint64_t h = hash(ptr);
    while (lock_counts[h].ptr != 0 && lock_counts[h].ptr != ptr) {
        h = (h + 1) % HASH_SIZE;
    }
    if (lock_counts[h].ptr == 0) {
        lock_counts[h].ptr = ptr;
        lock_counts[h].count = 1;
    } else {
        lock_counts[h].count++;
    }
}

static uint64_t get_lock_count(uint64_t ptr) {
    uint64_t h = hash(ptr);
    while (lock_counts[h].ptr != 0 && lock_counts[h].ptr != ptr) {
        h = (h + 1) % HASH_SIZE;
    }
    if (lock_counts[h].ptr == 0) {
        return 0;
    } else {
        return lock_counts[h].count;
    }
}

/*----------------------------------------------*/
/*                    hash                      */
/*----------------------------------------------*/


struct output_entry {
    int pid;
    char comm[16];
    long long delay;
};


struct output_entry seen_entries[MAX_ENTRIES];
int seen_count = 0;


bool entry_exists(int pid, const char *comm, long long delay) {
    for (int i = 0; i < seen_count; i++) {
        if (seen_entries[i].pid == pid &&
            strcmp(seen_entries[i].comm, comm) == 0 &&
            seen_entries[i].delay == delay) {
            return true;
        }
    }
    return false;
}


void add_entry(int pid, const char *comm, long long delay) {
    if (seen_count < MAX_ENTRIES) {
        seen_entries[seen_count].pid = pid;
        strncpy(seen_entries[seen_count].comm, comm, sizeof(seen_entries[seen_count].comm));
        seen_entries[seen_count].delay = delay;
        seen_count++;
    }
}
/*----------------------------------------------*/
/*                   uprobe                     */
/*----------------------------------------------*/
static const char object[] = "/usr/lib/x86_64-linux-gnu/libc.so.6";

#define __ATTACH_UPROBE(skel, sym_name, prog_name, is_retprobe)  \
    do                                                           \
    {                                                            \
		LIBBPF_OPTS(bpf_uprobe_opts, uprobe_opts,                \
                    .retprobe = is_retprobe,                     \
                    .func_name = #sym_name);                     \
        skel->links.prog_name = bpf_program__attach_uprobe_opts( \
            skel->progs.prog_name,                               \
            -1,                                                 \
            object,                                              \
            0,                                                   \
            &uprobe_opts);                                       \
    } while (false)

#define __CHECK_PROGRAM(skel, prog_name)                                                      \
    do                                                                                        \
    {                                                                                         \
        if (!skel->links.prog_name)                                                           \
        {                                                                                     \
            fprintf(stderr, "[%s] no program attached for" #prog_name "\n", strerror(errno)); \
            return -errno;                                                                    \
        }                                                                                     \
    } while (false)

#define __ATTACH_UPROBE_CHECKED(skel, sym_name, prog_name, is_retprobe) \
    do                                                                  \
    {                                                                   \
        __ATTACH_UPROBE(skel, sym_name, prog_name, is_retprobe);        \
        __CHECK_PROGRAM(skel, prog_name);                               \
    } while (false)

#define ATTACH_UPROBE(skel, sym_name, prog_name) __ATTACH_UPROBE(skel, sym_name, prog_name, false)
#define ATTACH_URETPROBE(skel, sym_name, prog_name) __ATTACH_UPROBE(skel, sym_name, prog_name, true)

#define ATTACH_UPROBE_CHECKED(skel, sym_name, prog_name) __ATTACH_UPROBE_CHECKED(skel, sym_name, prog_name, false)
#define ATTACH_URETPROBE_CHECKED(skel, sym_name, prog_name) __ATTACH_UPROBE_CHECKED(skel, sym_name, prog_name, true)

#define CHECK_ERR(cond, info)                               \
    if (cond)                                               \
    {                                                       \
        fprintf(stderr, "[%s]" info "\n", strerror(errno));                                   \
        return -1;                                          \
    }

#define warn(...) fprintf(stderr, __VA_ARGS__)


#endif // CPU_WATCHER_HELPER_H