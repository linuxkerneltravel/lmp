// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2020 Facebook */
#include <signal.h>
#include <stdio.h>
#include <time.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <unistd.h>
#include <stdlib.h>
#include <inttypes.h>
#include <linux/fs.h>
#include <errno.h>
#include <argp.h>
#include "open.skel.h"
#include "read.skel.h"
#include "write.skel.h"
#include "fs_watcher.h"

const char argp_program_doc[] = "fs_watcher is in use ....\n";

#define PROCESS_SKEL(skel, func) \
    skel = func##_bpf__open(); \
    if (!skel) { \
        fprintf(stderr, "Failed to open and load BPF skeleton\n"); \
        return 1; \
    } \
    process_##func(skel)


#define POLL_RING_BUFFER(rb, timeout, err)     \
    while (!exiting) {                         \
        err = ring_buffer__poll(rb, timeout);  \
        if (err == -EINTR) {                   \
            err = 0;                           \
            break;                             \
        }                                      \
        if (err < 0) {                         \
            printf("Error polling perf buffer: %d\n", err); \
            break;                             \
        }                                      \
    }

#define LOAD_AND_ATTACH_SKELETON(skel, event) \
    do {                                             \
        err = event##_bpf__load(skel);               \
        if (err) {                                   \
            fprintf(stderr, "Failed to load and verify BPF skeleton\n"); \
            goto event##_cleanup;                     \
        }                                            \
                                                     \
        err = event##_bpf__attach(skel);             \
        if (err) {                                   \
            fprintf(stderr, "Failed to attach BPF skeleton\n"); \
            goto event##_cleanup;                     \
        }                                            \
                                                     \
        rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_event_##event, NULL, NULL); \
        if (!rb) {                                   \
            fprintf(stderr, "Failed to create ring buffer\n"); \
            goto event##_cleanup;                     \
        }                                            \
    } while(0)


#define LOAD_AND_ATTACH_SKELETON_MAP(skel, event) \
    do {                                             \
        err = event##_bpf__load(skel);               \
        if (err) {                                   \
            fprintf(stderr, "Failed to load and verify BPF skeleton\n"); \
            goto event##_cleanup;                     \
        }                                            \
                                                     \
        err = event##_bpf__attach(skel);             \
        if (err) {                                   \
            fprintf(stderr, "Failed to attach BPF skeleton\n"); \
            goto event##_cleanup;                     \
        }                                            \
                                                     \
        int map_fd = bpf_map__fd(skel->maps.data);    \
        if(!map_fd){                                   \
            fprintf(stderr, "Failed to find BPF map\n");        \
            return -1;                                           \
        }                                                          \
        rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_event_##event, &map_fd, NULL); \
        if (!rb) {                                   \
            fprintf(stderr, "Failed to create ring buffer\n"); \
            goto event##_cleanup;                     \
        }                                            \
    } while(0)

static struct env{
    bool open;
    bool read;
    bool write;
}env = {
    .open = false,
    .read = false,
    .write = false,
};

static const struct argp_option opts[] = {
    {"select-function", 0, 0, 0, "Select function:", 1},
    
    {"open", 'o', 0, 0, "Print open (open系统调用检测报告)"},
    
    {"read", 'r', 0, 0, "Print read (read系统调用检测报告)"},
    
    {"write", 'w', 0, 0, "Print write (write系统调用检测报告)"},
    
    {0} // 结束标记，用于指示选项列表的结束
};


static error_t parse_arg(int key, char *arg, struct argp_state *state) {
    switch(key){
        case 'o':
        env.open = true;break;
        case 'r':
        env.read = true;break;
        case 'w':
        env.write = true;break;
        default: 
            return ARGP_ERR_UNKNOWN;
    }
    return 0;
}

static const struct argp argp = {
    .options = opts,
    .parser = parse_arg,
    .doc = argp_program_doc,
};
#define warn(...) fprintf(stderr, __VA_ARGS__)

static int libbpf_print_fn(enum libbpf_print_level level, const char *format,
			   va_list args)
{
	return vfprintf(stderr, format, args);
}

static volatile bool exiting = false;

static void sig_handler(int sig)
{
	exiting = true;
}

static int handle_event_open(void *ctx, void *data, size_t data_sz);
static int handle_event_read(void *ctx, void *data, size_t data_sz);
static int handle_event_write(void *ctx, void *data, size_t data_sz);

static int process_open(struct open_bpf *skel_open);
static int process_read(struct read_bpf *skel_read);
static int process_write(struct write_bpf *skel_write);




int main(int argc,char **argv){
    
    int err;
    struct open_bpf *skel_open;
    
    struct read_bpf *skel_read;
    struct write_bpf *skel_write;
    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
     

        /* Set up libbpf errors and debug info callback */
	libbpf_set_print(libbpf_print_fn);
	
    /* Cleaner handling of Ctrl-C */
	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);
    signal(SIGALRM, sig_handler);
   

    err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
      printf("success!\n");
    if (err)
        return err;

    if(env.open){
        PROCESS_SKEL(skel_open,open);
    }else if(env.read){
        PROCESS_SKEL(skel_read,read);
    }else if(env.write){
        PROCESS_SKEL(skel_write,write);
    }

}

    static int handle_event_open(void *ctx, void *data, size_t data_sz)
{
	struct event_open *e = (struct event_open *)data;
	char *filename = strrchr(e->path_name_, '/');
	++filename;

	char fd_path[path_size];
	char actual_path[path_size];
    char comm[TASK_COMM_LEN];
	int i = 0;
    int map_fd = *(int *)ctx;//传递map得文件描述符
    

	for (; i < e->n_; ++i) {
		snprintf(fd_path, sizeof(fd_path), "/proc/%d/fd/%d", e->pid_,
			 i);
		ssize_t len =
			readlink(fd_path, actual_path, sizeof(actual_path) - 1);
		if (len != -1) {
			actual_path[len] = '\0';
			int result = strcmp(e->path_name_, actual_path);
			if (result == 0) {
                if(bpf_map_lookup_elem(map_fd,&e->pid_,&comm)==0){
                    printf("get     ,   filename:%s    ,  fd:%d	, pid:%d  ,comm:%s\n",
				       e->path_name_, i,e->pid_,comm);
                }else{
                    fprintf(stderr, "Failed to lookup value for key %d\n", e->pid_);
                    }
				
			    }
		    }
	    }
	return 0;
}


static int handle_event_read(void *ctx, void *data, size_t data_sz)
{
	const struct event_read *e = data;
	struct tm *tm;
	char ts[32];
	time_t t;

	time(&t);
	tm = localtime(&t);
	strftime(ts, sizeof(ts), "%H:%M:%S", tm);

	printf("%-8s  %-7d  %-7llu\n", ts, e->pid,e->duration_ns);
	return 0;
}

static int handle_event_write(void *ctx, void *data, size_t data_sz)
{
    const struct fs_t *e = data;
    struct tm *tm;
    char ts[32];
    time_t t;
    time(&t);
    tm = localtime(&t);
    strftime(ts, sizeof(ts), "%H:%M:%S", tm);
	printf("ts:%-8s  pid:%-7ld inode_number:%-3ld  cout:%-3ld   real_count:%-3ld\n", ts, e->pid,e->inode_number,e->count,e->real_count);
    return 0;
}

static int process_open(struct open_bpf *skel_open){
    int err;
    struct ring_buffer *rb;
    
    LOAD_AND_ATTACH_SKELETON_MAP(skel_open,open);

    printf("%-8s    %-8s    %-8s    %-8s\n","filenamename","fd","pid","comm");
    POLL_RING_BUFFER(rb, 1000, err);

open_cleanup:
    ring_buffer__free(rb);
    open_bpf__destroy(skel_open);

    return err;
}

static int process_read(struct read_bpf *skel_read){
    int err;
    struct ring_buffer *rb;
    
    LOAD_AND_ATTACH_SKELETON(skel_read,read);

    printf("%-8s    %-8s    %-8s    %-8s\n","filename","fd","pid","ds");
    POLL_RING_BUFFER(rb, 1000, err);

read_cleanup:
    ring_buffer__free(rb);
    read_bpf__destroy(skel_read);

    return err;
}

static int process_write(struct write_bpf *skel_write){
    int err;
    struct ring_buffer *rb;
    
    LOAD_AND_ATTACH_SKELETON(skel_write,write);

    printf("%-8s    %-8s    %-8s    %-8s    %-8s\n","ds","inode_number","pid","real_count","count");
    POLL_RING_BUFFER(rb, 1000, err);

write_cleanup:
    ring_buffer__free(rb);
    write_bpf__destroy(skel_write);

    return err;
}

