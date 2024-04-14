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
// user-mode helper functions for the process image

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

typedef long long unsigned int u64;
typedef unsigned int u32;

#define NR_syscalls 500

#define RESOURCE_IMAGE 1
#define SYSCALL_IMAGE 2
#define LOCK_IMAGE 3
#define KEYTIME_IMAGE 4
#define SCHEDULE_IMAGE 5

const char *rsc_ctrl_path =  "/sys/fs/bpf/proc_image_map/rsc_ctrl_map";
const char *kt_ctrl_path = "/sys/fs/bpf/proc_image_map/kt_ctrl_map";
const char *lock_ctrl_path = "/sys/fs/bpf/proc_image_map/lock_ctrl_map";
const char *sched_ctrl_path = "/sys/fs/bpf/proc_image_map/sched_ctrl_map";
const char *sc_ctrl_path = "/sys/fs/bpf/proc_image_map/sc_ctrl_map";

struct proc_syscall_info {
    int first_syscall;
    int second_syscall;
    int third_syscall;
    u32 syscalls [NR_syscalls];
};

struct syscall_hash {
	int key;    // pid
    struct proc_syscall_info value;
};

int user_compare(const void *a, const void *b, void *udata) {
    const struct syscall_hash *ua = a;
    const struct syscall_hash *ub = b;
    int ret = ua->key - ub->key;
    return ret;
}

uint64_t user_hash(const void *item, uint64_t seed0, uint64_t seed1) {
    const struct syscall_hash *user = item;
    char key_str[20];
    sprintf(key_str, "%d", user->key);
    return hashmap_sip(key_str, strlen(key_str), seed0, seed1);
}

void update_syscalls(u32 *syscalls, const struct syscall_seq *e, int *first_syscall,
                     int *second_syscall, int *third_syscall){
    int tmp;
    
    for(int i=0; i<e->count; i++){
		syscalls[e->record_syscall[i]] ++;

		if(e->record_syscall[i]==*first_syscall || e->record_syscall[i]==*second_syscall || e->record_syscall[i]==*third_syscall){
			// 将前三名进行冒泡排序
			if(syscalls[*third_syscall] > syscalls[*second_syscall]){
				tmp = *second_syscall;
				*second_syscall = *third_syscall;
				*third_syscall = tmp;
			}
			if(syscalls[*second_syscall] > syscalls[*first_syscall]){
				tmp = *first_syscall;
				*first_syscall = *second_syscall;
				*second_syscall = tmp;
			}
			if(syscalls[*third_syscall] > syscalls[*second_syscall]){
				tmp = *second_syscall;
				*second_syscall = *third_syscall;
				*third_syscall = tmp;
			}
		}else if(syscalls[e->record_syscall[i]] > syscalls[*third_syscall]){
			if(syscalls[e->record_syscall[i]] > syscalls[*second_syscall]){
				if(syscalls[e->record_syscall[i]] > syscalls[*first_syscall]){
					*third_syscall = *second_syscall;
					*second_syscall = *first_syscall;
					*first_syscall = e->record_syscall[i];
					continue;
				}
				*third_syscall = *second_syscall;
				*second_syscall = e->record_syscall[i];
				continue;
			}
			*third_syscall = e->record_syscall[i];
		}
	}
}

int common_pin_map(struct bpf_map **bpf_map, const struct bpf_object *obj, const char *map_name, const char *ctrl_path)
{
    int ret;
    
    *bpf_map = bpf_object__find_map_by_name(obj, map_name);
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
    }
	
    return 0;
}

int update_rsc_ctrl_map(struct rsc_ctrl rsc_ctrl){
	int err,key = 0;
	int srcmap_fd;
	
	srcmap_fd = bpf_obj_get(rsc_ctrl_path);
    if (srcmap_fd < 0) {
        fprintf(stderr,"Failed to open rsc_ctrl_map file\n");
        return srcmap_fd;
    }
    err = bpf_map_update_elem(srcmap_fd,&key,&rsc_ctrl, 0);
    if(err < 0){
        fprintf(stderr, "Failed to update rsc_ctrl_map elem\n");
        return err;
    }

    return 0;
}

int update_kt_ctrl_map(struct kt_ctrl kt_ctrl){
	int err,key = 0;
	int ktmap_fd;
	
	ktmap_fd = bpf_obj_get(kt_ctrl_path);
    if (ktmap_fd < 0) {
        fprintf(stderr,"Failed to open kt_ctrl_map file\n");
        return ktmap_fd;
    }
    err = bpf_map_update_elem(ktmap_fd,&key,&kt_ctrl, 0);
    if(err < 0){
        fprintf(stderr, "Failed to update kt_ctrl_map elem\n");
        return err;
    }

    return 0;
}

int update_lock_ctrl_map(struct lock_ctrl lock_ctrl){
	int err,key = 0;
	int lockmap_fd;
	
	lockmap_fd = bpf_obj_get(lock_ctrl_path);
    if (lockmap_fd < 0) {
        fprintf(stderr,"Failed to open lock_ctrl_map file\n");
        return lockmap_fd;
    }
    err = bpf_map_update_elem(lockmap_fd,&key,&lock_ctrl, 0);
    if(err < 0){
        fprintf(stderr, "Failed to update lock_ctrl_map elem\n");
        return err;
    }

    return 0;
}

int update_sc_ctrl_map(struct sc_ctrl sc_ctrl){
	int err,key = 0;
	int scmap_fd;
	
	scmap_fd = bpf_obj_get(sc_ctrl_path);
    if (scmap_fd < 0) {
        fprintf(stderr,"Failed to open sc_ctrl_map file\n");
        return scmap_fd;
    }
    err = bpf_map_update_elem(scmap_fd,&key,&sc_ctrl, 0);
    if(err < 0){
        fprintf(stderr, "Failed to update sc_ctrl_map elem\n");
        return err;
    }

    return 0;
}

int update_sched_ctrl_map(struct sched_ctrl sched_ctrl){
	int err,key = 0;
	int schedmap_fd;
	
	schedmap_fd = bpf_obj_get(sched_ctrl_path);
    if (schedmap_fd < 0) {
        fprintf(stderr,"Failed to open sched_ctrl_map file\n");
        return schedmap_fd;
    }
    err = bpf_map_update_elem(schedmap_fd,&key,&sched_ctrl, 0);
    if(err < 0){
        fprintf(stderr, "Failed to update sched_ctrl_map elem\n");
        return err;
    }

    return 0;
}