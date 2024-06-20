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
// author: 3174314597@qq.com
//
// mem_watcher libbpf user mode code

#include <assert.h>
#include <argp.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <time.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <sys/select.h>
#include <unistd.h>
#include "paf.skel.h"
#include "pr.skel.h"
#include "procstat.skel.h"
#include "sysstat.skel.h"
#include "memleak.skel.h"
#include "mem_watcher.h"

#include "blazesym.h"

static const int perf_max_stack_depth = 127;    //stack id 对应的堆栈的深度
static const int stack_map_max_entries = 10240; //最大允许存储多少个stack_id
static __u64 *g_stacks = NULL;
static size_t g_stacks_size = 0;

#define KERN_STACKID_FLAGS (0 | BPF_F_FAST_STACK_CMP)
#define USER_STACKID_FLAGS (0 | BPF_F_FAST_STACK_CMP | BPF_F_USER_STACK)

static struct blaze_symbolizer *symbolizer;

static int attach_pid;
pid_t own_pid;
static char binary_path[128] = { 0 };

struct allocation {
	int stack_id;
	__u64 size;
	size_t count;
};

static struct allocation *allocs;

static volatile bool exiting = false;

#define __ATTACH_UPROBE(skel, sym_name, prog_name, is_retprobe) \
    do { \
        LIBBPF_OPTS(bpf_uprobe_opts, uprobe_opts, \
                .func_name = #sym_name, \
                .retprobe = is_retprobe); \
        skel->links.prog_name = bpf_program__attach_uprobe_opts( \
                skel->progs.prog_name, \
                attach_pid, \
                binary_path, \
                0, \
                &uprobe_opts); \
    } while (false)
 
#define __CHECK_PROGRAM(skel, prog_name) \
    do { \
        if (!skel->links.prog_name) { \
            perror("no program attached for " #prog_name); \
            return -errno; \
        } \
    } while (false)
 
#define __ATTACH_UPROBE_CHECKED(skel, sym_name, prog_name, is_retprobe) \
    do { \
        __ATTACH_UPROBE(skel, sym_name, prog_name, is_retprobe); \
        __CHECK_PROGRAM(skel, prog_name); \
    } while (false)

#define ATTACH_UPROBE(skel, sym_name, prog_name) __ATTACH_UPROBE(skel, sym_name, prog_name, false)
#define ATTACH_URETPROBE(skel, sym_name, prog_name) __ATTACH_UPROBE(skel, sym_name, prog_name, true)
 
#define ATTACH_UPROBE_CHECKED(skel, sym_name, prog_name) __ATTACH_UPROBE_CHECKED(skel, sym_name, prog_name, false)
#define ATTACH_URETPROBE_CHECKED(skel, sym_name, prog_name) __ATTACH_UPROBE_CHECKED(skel, sym_name, prog_name, true)

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
        skel->bss->user_pid = own_pid;              \
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

static struct env {
	int time;
	bool paf;
	bool pr;
	bool procstat;
	bool sysstat;
	bool memleak;
	bool kernel_trace;
	bool print_time;

	bool part2;

	long choose_pid;
	bool rss;
} env = {
	.time = 0,
	.paf = false,
	.pr = false,
	.procstat = false,
	.sysstat = false,
	.memleak = false,
	.kernel_trace = true,
	.print_time = false,
	.rss = false,
	.part2 = false,
	.choose_pid = 0,
};

const char argp_program_doc[] = "mem_watcher is in use ....\n";

static const struct argp_option opts[] = {
	{0, 0, 0, 0, "select function:", 1},

	{0, 0, 0, 0, "par:", 2},
	{"paf", 'a', 0, 0, "print paf (内存页面状态报告)"},

	{0, 0, 0, 0, "pr:", 3},
	{"pr", 'p', 0, 0, "print pr (页面回收状态报告)"},

	{0, 0, 0, 0, "procstat:", 4},
	{"procstat", 'r', 0, 0, "print procstat (进程内存状态报告)"},
	{"choose_pid", 'P', "PID", 0, "选择进程号打印"},
	{"Rss", 'R', NULL, 0, "打印进程页面", 5},

	{0, 0, 0, 0, "sysstat:", 6},
	{"sysstat", 's', 0, 0, "print sysstat (系统内存状态报告)"},
	
	{"part2", 'n', NULL, 0, "系统内存状态报告2", 7},

	{0, 0, 0, 0, "memleak:", 8},
	{"memleak", 'l', 0, 0, "print memleak (内核态内存泄漏检测)", 8},
	{"choose_pid", 'P', "PID", 0, "选择进程号打印, print memleak (用户态内存泄漏检测)", 9},
	{"print_time", 'm', 0, 0, "打印申请地址时间 (用户态)", 10},


	{"time", 't', "TIME-SEC", 0, "Max Running Time(0 for infinite)", 11},
	{NULL, 'h', NULL, OPTION_HIDDEN, "show the full help"},
	{0},
};

static error_t parse_arg(int key, char *arg, struct argp_state *state) {
    switch (key) {
        case 't':
            env.time = strtol(arg, NULL, 10);
            if (env.time) alarm(env.time);
            break;
        case 'a': env.paf = true; break;
        case 'p': env.pr = true; break;
        case 'r': env.procstat = true; break;
        case 's': env.sysstat = true; break;
        case 'n': env.part2 = true; break;
        case 'P': env.choose_pid = strtol(arg, NULL, 10); break;
        case 'R': env.rss = true; break;
		    case 'l': env.memleak = true; break;
		    case 'm': env.print_time = true; break;
		    case 'h': argp_state_help(state, stderr, ARGP_HELP_STD_HELP); break;
		    default: return ARGP_ERR_UNKNOWN;
    }
    return 0;
}

static const struct argp argp = {
	.options = opts,
	.parser = parse_arg,
	.doc = argp_program_doc,
};

// Function prototypes
static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args);
static void sig_handler(int sig);
static void setup_signals(void);
static void disable_kernel_tracepoints(struct memleak_bpf *skel);
static void print_frame(const char *name, uintptr_t input_addr, uintptr_t addr, uint64_t offset, const blaze_symbolize_code_info *code_info);
static void show_stack_trace(__u64 *stack, int stack_sz, pid_t pid);
static int print_outstanding_allocs(struct memleak_bpf *skel);
static int print_outstanding_combined_allocs(struct memleak_bpf *skel, pid_t pid);
static int handle_event_paf(void *ctx, void *data, size_t data_sz);
static int handle_event_pr(void *ctx, void *data, size_t data_sz);
static int handle_event_procstat(void *ctx, void *data, size_t data_sz);
static int handle_event_sysstat(void *ctx, void *data, size_t data_sz);
static int attach_uprobes(struct memleak_bpf *skel);
static int process_paf(struct paf_bpf *skel_paf);
static int process_pr(struct pr_bpf *skel_pr);
static int process_procstat(struct procstat_bpf *skel_procstat);
static int process_sysstat(struct sysstat_bpf *skel_sysstat);
static int process_memleak(struct memleak_bpf *skel_memleak, struct env);
static __u64 adjust_time_to_program_start_time(__u64 first_query_time);
static int update_addr_times(struct memleak_bpf *skel_memleak);
static int print_time(struct memleak_bpf *skel_memleak);


// Main function
int main(int argc, char **argv) {
    int err;
    struct paf_bpf *skel_paf;
    struct pr_bpf *skel_pr;
    struct procstat_bpf *skel_procstat;
    struct sysstat_bpf *skel_sysstat;
    struct memleak_bpf *skel_memleak;

    err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
    if (err)
        return err;

    own_pid = getpid();
    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
    libbpf_set_print(libbpf_print_fn);

    setup_signals();

    if (env.paf) {
		PROCESS_SKEL(skel_paf, paf);
	} else if (env.pr) {
		PROCESS_SKEL(skel_pr, pr);
	} else if (env.procstat) {
		PROCESS_SKEL(skel_procstat, procstat);
	} else if (env.sysstat) {
		PROCESS_SKEL(skel_sysstat, sysstat);
    } else if (env.memleak) {
        if (env.choose_pid != 0) {
			printf("用户态内存泄漏\n");
			env.kernel_trace = false;
			attach_pid = env.choose_pid;
		}
		else
			attach_pid = 0;

		strcpy(binary_path, "/lib/x86_64-linux-gnu/libc.so.6");

		allocs = calloc(ALLOCS_MAX_ENTRIES, sizeof(*allocs));

		/* Set up libbpf errors and debug info callback */
		libbpf_set_print(libbpf_print_fn);

		/* Load and verify BPF application */
		skel_memleak = memleak_bpf__open();
		if (!skel_memleak) {
			fprintf(stderr, "Failed to open BPF skeleton\n");
			return 1;
		}
		process_memleak(skel_memleak, env);
	}
    return 0;
}

int alloc_size_compare(const void *a, const void *b)
{
	const struct allocation *x = (struct allocation *)a;
	const struct allocation *y = (struct allocation *)b;

	// descending order

	if (x->size > y->size)
		return -1;

	if (x->size < y->size)
		return 1;

	return 0;
}

static void print_frame(const char *name, uintptr_t input_addr, uintptr_t addr, uint64_t offset, const blaze_symbolize_code_info *code_info) {
	// If we have an input address  we have a new symbol.
	if (input_addr != 0) {
		printf("%016lx: %s @ 0x%lx+0x%lx", input_addr, name, addr, offset);
		if (code_info != NULL && code_info->dir != NULL && code_info->file != NULL) {
			printf(" %s/%s:%u\n", code_info->dir, code_info->file, code_info->line);
		}
		else if (code_info != NULL && code_info->file != NULL) {
			printf(" %s:%u\n", code_info->file, code_info->line);
		}
		else {
			printf("\n");
		}
	}
	else {
		printf("%16s  %s", "", name);
		if (code_info != NULL && code_info->dir != NULL && code_info->file != NULL) {
			printf("@ %s/%s:%u [inlined]\n", code_info->dir, code_info->file, code_info->line);
		}
		else if (code_info != NULL && code_info->file != NULL) {
			printf("@ %s:%u [inlined]\n", code_info->file, code_info->line);
		}
		else {
			printf("[inlined]\n");
		}
	}
}

static void show_stack_trace(__u64 *stack, int stack_sz, pid_t pid) {
	const struct blaze_symbolize_inlined_fn *inlined;
	const struct blaze_result *result;
	const struct blaze_sym *sym;
	int i, j;

	assert(sizeof(uintptr_t) == sizeof(uint64_t));

	if (pid) {
		struct blaze_symbolize_src_process src = {
			.type_size = sizeof(src),
			.pid = pid,
		};
		result = blaze_symbolize_process_abs_addrs(symbolizer, &src, (const uintptr_t *)stack, stack_sz);
	}
	else {
		struct blaze_symbolize_src_kernel src = {
			.type_size = sizeof(src),
		};
		result = blaze_symbolize_kernel_abs_addrs(symbolizer, &src, (const uintptr_t *)stack, stack_sz);
	}


	for (i = 0; i < stack_sz; i++) {
		if (!result || result->cnt <= i || result->syms[i].name == NULL) {
			printf("%016llx: <no-symbol>\n", stack[i]);
			continue;
		}

		sym = &result->syms[i];
		print_frame(sym->name, stack[i], sym->addr, sym->offset, &sym->code_info);

		for (j = 0; j < sym->inlined_cnt; j++) {
			inlined = &sym->inlined[j];
			print_frame(sym->name, 0, 0, 0, &inlined->code_info);
		}
	}

	blaze_result_free(result);
}

int print_outstanding_allocs(struct memleak_bpf *skel) {
	const size_t allocs_key_size = bpf_map__key_size(skel->maps.allocs);

	time_t t = time(NULL);
	struct tm *tm = localtime(&t);

	size_t nr_allocs = 0;

	// for each struct alloc_info "alloc_info" in the bpf map "allocs"
	for (__u64 prev_key = 0, curr_key = 0; ; prev_key = curr_key) {
		struct alloc_info alloc_info = {};
		memset(&alloc_info, 0, sizeof(alloc_info));

		if (bpf_map__get_next_key(skel->maps.allocs, &prev_key, &curr_key, allocs_key_size)) {
			if (errno == ENOENT) {
				break; // no more keys, done
			}

			perror("map get next key error");

			return -errno;
		}

		if (bpf_map__lookup_elem(skel->maps.allocs, &curr_key, allocs_key_size, &alloc_info, sizeof(alloc_info), 0)) {
			if (errno == ENOENT)
				continue;

			perror("map lookup error");

			return -errno;
		}

		// filter invalid stacks
		if (alloc_info.stack_id < 0) {
			continue;
		}

		// when the stack_id exists in the allocs array,
		//   increment size with alloc_info.size
		bool stack_exists = false;

		for (size_t i = 0; !stack_exists && i < nr_allocs; ++i) {
			struct allocation *alloc = &allocs[i];

			if (alloc->stack_id == alloc_info.stack_id) {
				alloc->size += alloc_info.size;
				alloc->count++;

				stack_exists = true;
				break;
			}
		}

		if (stack_exists)
			continue;

		// when the stack_id does not exist in the allocs array,
		//   create a new entry in the array
		struct allocation alloc = {
			.stack_id = alloc_info.stack_id,
			.size = alloc_info.size,
			.count = 1,
		};

		memcpy(&allocs[nr_allocs], &alloc, sizeof(alloc));
		nr_allocs++;
	}

	// sort the allocs array in descending order
	qsort(allocs, nr_allocs, sizeof(allocs[0]), alloc_size_compare);

	// get min of allocs we stored vs the top N requested stacks
	size_t nr_allocs_to_show = nr_allocs < 10 ? nr_allocs : 10;

	printf("[%d:%d:%d] Top %zu stacks with outstanding allocations:\n",
		tm->tm_hour, tm->tm_min, tm->tm_sec, nr_allocs_to_show);

	for (size_t i = 0; i < nr_allocs_to_show;i++) {
		if (bpf_map__lookup_elem(skel->maps.stack_traces,
            &allocs[i].stack_id, sizeof(allocs[i].stack_id), g_stacks, g_stacks_size, 0)) {
            perror("failed to lookup stack traces!");
            return -errno;
        }
	}

	show_stack_trace(g_stacks, nr_allocs_to_show, 0);

	return 0;
}

int print_outstanding_combined_allocs(struct memleak_bpf *skel, pid_t pid) {
    const size_t combined_allocs_key_size = bpf_map__key_size(skel->maps.combined_allocs);
    const size_t stack_traces_key_size = bpf_map__key_size(skel->maps.stack_traces);

    for (__u64 prev_key = 0, curr_key = 0; ; prev_key = curr_key) {

        if (bpf_map__get_next_key(skel->maps.combined_allocs,
            &prev_key, &curr_key, combined_allocs_key_size)) {
            if (errno == ENOENT) {
                break; //no more keys, done!
            }
            perror("map get next key failed!");

            return -errno;
        }

        // stack_id = curr_key
        union combined_alloc_info cinfo;
        memset(&cinfo, 0, sizeof(cinfo));

        if (bpf_map__lookup_elem(skel->maps.combined_allocs,
            &curr_key, combined_allocs_key_size, &cinfo, sizeof(cinfo), 0)) {
            if (errno == ENOENT) {
                continue;
            }

            perror("map lookup failed!");
            return -errno;
        }

        if (bpf_map__lookup_elem(skel->maps.stack_traces,
            &curr_key, stack_traces_key_size, g_stacks, g_stacks_size, 0)) {
            perror("failed to lookup stack traces!");
            return -errno;
        }

        printf("stack_id=0x%llx with outstanding allocations: total_size=%llu nr_allocs=%llu\n",
            curr_key, (__u64)cinfo.total_size, (__u64)cinfo.number_of_allocs);

        int stack_sz = 0;
        for (int i = 0; i < perf_max_stack_depth; i++) {
            if (g_stacks[i] == 0) {
                break;
            }
            stack_sz++;
            //printf("[%3d] 0x%llx\n", i, g_stacks[i]);
        }

        show_stack_trace(g_stacks, stack_sz, pid);
    }

    return 0;
}

// 在更新时间之前获取当前时间并调整为相对于程序启动时的时间
static __u64 adjust_time_to_program_start_time(__u64 first_query_time) {
    struct timespec current_time;
    clock_gettime(CLOCK_MONOTONIC, &current_time);
    //printf("current_time: %ld\n", current_time.tv_sec);
    __u64 adjusted_time;
    adjusted_time = current_time.tv_sec - first_query_time;

    //printf("adjusted_time: %lld\n", adjusted_time);
    return adjusted_time;
}


// 在更新时间时，先将时间调整为相对于程序启动的时间
static int update_addr_times(struct memleak_bpf *skel) {
    const size_t addr_times_key_size = bpf_map__key_size(skel->maps.addr_times);
    const size_t first_time_key_size = bpf_map__key_size(skel->maps.first_time);
    for (__u64 prev_key = 0, curr_key = 0;; prev_key = curr_key) {
        if (bpf_map__get_next_key(skel->maps.addr_times, &prev_key, &curr_key, addr_times_key_size)) {
            if (errno == ENOENT) {
                break; // no more keys, done!
            }

            perror("map get next key failed!");
            return -errno;
        }

        // Check if the address exists in the first_time map
        __u64 first_query_time;
        if (bpf_map__lookup_elem(skel->maps.first_time, &curr_key, first_time_key_size, &first_query_time, sizeof(first_query_time), 0)) {
            // Address doesn't exist in the first_time map, add it with the current time
            struct timespec first_time_alloc;
            clock_gettime(CLOCK_MONOTONIC, &first_time_alloc);
            if (bpf_map__update_elem(skel->maps.first_time, &curr_key, first_time_key_size, &first_time_alloc.tv_sec, sizeof(first_time_alloc.tv_sec), 0)) {
                perror("map update failed!");
                return -errno;
            }
        }
        else {
            // Address exists in the first_time map
            // This is the first time updating timestamp
            __u64 adjusted_time = adjust_time_to_program_start_time(first_query_time);
            //printf("update_addr_times adjusted_time: %lld\n", adjusted_time);

            // Save the adjusted time to addr_times map
            __u64 timestamp = adjusted_time;

            // write the updated timestamp back to the map
            if (bpf_map__update_elem(skel->maps.addr_times, &curr_key, addr_times_key_size, &timestamp, sizeof(timestamp), 0)) {
                perror("map update failed!");
                return -errno;
            }
        }
    }
    return 0;
}

// 在打印时间时，先将时间调整为相对于程序启动的时间
int print_time(struct memleak_bpf *skel) {
    const size_t addr_times_key_size = bpf_map__key_size(skel->maps.addr_times);

    printf("%-16s %12s\n", "AL_ADDR", "AL_Time(s)");

    // Iterate over the addr_times map to print address and time
    for (__u64 prev_key = 0, curr_key = 0;; prev_key = curr_key) {
        if (bpf_map__get_next_key(skel->maps.addr_times, &prev_key, &curr_key, addr_times_key_size)) {
            if (errno == ENOENT) {
                break; // no more keys, done!
            }
            perror("map get next key failed!");
            return -errno;
        }

        // Read the timestamp for the current address
        __u64 timestamp;
        if (bpf_map__lookup_elem(skel->maps.addr_times, &curr_key, addr_times_key_size, &timestamp, sizeof(timestamp), 0) == 0) {
            printf("0x%-16llx %lld\n", curr_key, timestamp);
        }
        else {
            perror("map lookup failed!");
            return -errno;
        }
    }
    return 0;
}

void disable_kernel_tracepoints(struct memleak_bpf *skel) {
	bpf_program__set_autoload(skel->progs.memleak__kmalloc, false);
	bpf_program__set_autoload(skel->progs.memleak__kmalloc_node, false);
	bpf_program__set_autoload(skel->progs.memleak__kfree, false);
	bpf_program__set_autoload(skel->progs.memleak__kmem_cache_alloc, false);
	bpf_program__set_autoload(skel->progs.memleak__kmem_cache_alloc_node, false);
	bpf_program__set_autoload(skel->progs.memleak__kmem_cache_free, false);
	bpf_program__set_autoload(skel->progs.memleak__mm_page_alloc, false);
	bpf_program__set_autoload(skel->progs.memleak__mm_page_free, false);
}

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args) {
	return vfprintf(stderr, format, args);
}

static void sig_handler(int sig) {
	exiting = true;
	exit(EXIT_SUCCESS); 
}

static void setup_signals(void) {
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);
    signal(SIGALRM, sig_handler);
}

/*
static char* flags(int flag)
{
	if(flag & GFP_ATOMIC)
		return "GFP_ATOMIC";
	if(flag & GFP_KERNEL)
		return "GFP_KERNEL";
	if(flag & GFP_KERNEL_ACCOUNT)
		return "GFP_KERNEL_ACCOUNT";
	if(flag & GFP_NOWAIT)
		return "GFP_NOWAIT";
	if(flag & GFP_NOIO )
		return "GFP_NOIO ";
	if(flag & GFP_NOFS)
		return "GFP_NOFS";
	if(flag & GFP_USER)
		return "GFP_USER";
	if(flag & GFP_DMA)
		return "GFP_DMA";
	if(flag & GFP_DMA32)
		return "GFP_DMA32";
	if(flag & GFP_HIGHUSER)
		return "GFP_HIGHUSER";
	if(flag & GFP_HIGHUSER_MOVABLE)
		return "GFP_HIGHUSER_MOVABLE";
	if(flag & GFP_TRANSHUGE_LIGHT)
		return "GFP_TRANSHUGE_LIGHT";
	return;
}
*/
static int handle_event_paf(void *ctx, void *data, size_t data_sz) {
	const struct paf_event *e = data;
	struct tm *tm;
	char ts[32];
	time_t t;

	time(&t);
	tm = localtime(&t);
	strftime(ts, sizeof(ts), "%H:%M:%S", tm);

	printf("%-8lu %-8lu  %-8lu %-8lu %-8x\n",
		e->min, e->low, e->high, e->present, e->flag);

	return 0;
}

static int handle_event_pr(void *ctx, void *data, size_t data_sz) {
	const struct pr_event *e = data;
	struct tm *tm;
	char ts[32];
	time_t t;

	time(&t);
	tm = localtime(&t);
	strftime(ts, sizeof(ts), "%H:%M:%S", tm);

	printf("%-8lu %-8lu  %-8u %-8u %-8u\n",
		e->reclaim, e->reclaimed, e->unqueued_dirty, e->congested, e->writeback);

	return 0;
}

static int handle_event_procstat(void *ctx, void *data, size_t data_sz) {
	const struct procstat_event *e = data;
	struct tm *tm;
	char ts[32];
	time_t t;

	time(&t);
	tm = localtime(&t);
	strftime(ts, sizeof(ts), "%H:%M:%S", tm);
	if (env.choose_pid) {
		if (e->pid == env.choose_pid) {
			if (env.rss == true)
				printf("%-8s %-8d %-8ld %-8ld %-8ld %-8lld %-8lld\n", ts, e->pid, e->vsize, e->Vdata, e->Vstk, e->VPTE, e->vswap);
			else
				printf("%-8s %-8d %-8ld %-8lld %-8lld %-8lld\n", ts, e->pid, e->size, e->rssanon, e->rssfile, e->rssshmem);
		}
	}
	else {
		if (env.rss == true)
			printf("%-8s %-8d %-8ld %-8ld %-8ld %-8lld %-8lld\n", ts, e->pid, e->vsize, e->Vdata, e->Vstk, e->VPTE, e->vswap);
		else
			printf("%-8s %-8d %-8ld %-8lld %-8lld %-8lld\n", ts, e->pid, e->size, e->rssanon, e->rssfile, e->rssshmem);
	}

	return 0;
}

static int handle_event_sysstat(void *ctx, void *data, size_t data_sz) {
	const struct sysstat_event *e = data;
	struct tm *tm;
	char ts[32];
	time_t t;

	time(&t);
	tm = localtime(&t);
	strftime(ts, sizeof(ts), "%H:%M:%S", tm);

	if (env.part2 == true)
		printf("%-8lu %-8lu %-8lu %-8lu %-8lu %-8lu %-8lu %-8lu %-8lu\n", e->slab_reclaimable + e->kernel_misc_reclaimable, e->slab_reclaimable + e->slab_unreclaimable, e->slab_reclaimable, e->slab_unreclaimable, e->unstable_nfs, e->writeback_temp, e->anon_thps, e->shmem_thps, e->pmdmapped);
	else
		printf("%-8lu %-8lu %-8lu %-8lu %-8lu %-8lu %-8lu %-8lu %-8lu %-8lu %-8lu %-8lu\n", e->anon_active + e->file_active, e->file_inactive + e->anon_inactive, e->anon_active, e->anon_inactive, e->file_active, e->file_inactive, e->unevictable, e->file_dirty, e->writeback, e->anon_mapped, e->file_mapped, e->shmem);

	return 0;
}

int attach_uprobes(struct memleak_bpf *skel) {
    ATTACH_UPROBE_CHECKED(skel, malloc, malloc_enter);
    ATTACH_URETPROBE_CHECKED(skel, malloc, malloc_exit);
    ATTACH_UPROBE_CHECKED(skel, free, free_enter);

    ATTACH_UPROBE_CHECKED(skel, posix_memalign, posix_memalign_enter);
    ATTACH_URETPROBE_CHECKED(skel, posix_memalign, posix_memalign_exit);

    ATTACH_UPROBE_CHECKED(skel, calloc, calloc_enter);
    ATTACH_URETPROBE_CHECKED(skel, calloc, calloc_exit);

    ATTACH_UPROBE_CHECKED(skel, realloc, realloc_enter);
    ATTACH_URETPROBE_CHECKED(skel, realloc, realloc_exit);

    ATTACH_UPROBE_CHECKED(skel, mmap, mmap_enter);
    ATTACH_URETPROBE_CHECKED(skel, mmap, mmap_exit);

    ATTACH_UPROBE_CHECKED(skel, memalign, memalign_enter);
    ATTACH_URETPROBE_CHECKED(skel, memalign, memalign_exit);

    ATTACH_UPROBE_CHECKED(skel, free, free_enter);
    ATTACH_UPROBE_CHECKED(skel, munmap, munmap_enter);

    // the following probes are intentinally allowed to fail attachment

    // deprecated in libc.so bionic
    ATTACH_UPROBE(skel, valloc, valloc_enter);
    ATTACH_URETPROBE(skel, valloc, valloc_exit);

    // deprecated in libc.so bionic
    ATTACH_UPROBE(skel, pvalloc, pvalloc_enter);
    ATTACH_URETPROBE(skel, pvalloc, pvalloc_exit);

    // added in C11
    ATTACH_UPROBE(skel, aligned_alloc, aligned_alloc_enter);
    ATTACH_URETPROBE(skel, aligned_alloc, aligned_alloc_exit);

    return 0;
}

// Functions to process different BPF programs
static int process_paf(struct paf_bpf *skel_paf) {
    int err;
    struct ring_buffer *rb;

    LOAD_AND_ATTACH_SKELETON(skel_paf, paf);

    printf("%-8s %-8s  %-8s %-8s %-8s\n", "MIN", "LOW", "HIGH", "PRESENT", "FLAG");

	POLL_RING_BUFFER(rb, 1000, err);

paf_cleanup:
	ring_buffer__free(rb);
	paf_bpf__destroy(skel_paf);
    return err;
}

static int process_pr(struct pr_bpf *skel_pr) {
    int err;
    struct ring_buffer *rb;

    LOAD_AND_ATTACH_SKELETON(skel_pr, pr);

    printf("%-8s %-8s %-8s %-8s %-8s\n", "RECLAIM", "RECLAIMED", "UNQUEUE", "CONGESTED", "WRITEBACK");

	POLL_RING_BUFFER(rb, 1000, err);

pr_cleanup:
	ring_buffer__free(rb);
	pr_bpf__destroy(skel_pr);
    return err;
}

static int process_procstat(struct procstat_bpf *skel_procstat) {
    int err;
    struct ring_buffer *rb;

    LOAD_AND_ATTACH_SKELETON(skel_procstat, procstat);

    if (env.rss) {
        printf("%-8s %-8s %-8s %-8s %-8s %-8s %-8s\n", "TIME", "PID", "VMSIZE", "VMDATA", "VMSTK", "VMPTE", "VMSWAP");
    } else {
        printf("%-8s %-8s %-8s %-8s %-8s %-8s\n", "TIME", "PID", "SIZE", "RSSANON", "RSSFILE", "RSSSHMEM");
    }

	POLL_RING_BUFFER(rb, 1000, err);

procstat_cleanup:
	ring_buffer__free(rb);
	procstat_bpf__destroy(skel_procstat);
    return err;
}

static int process_sysstat(struct sysstat_bpf *skel_sysstat) {
    int err;
    struct ring_buffer *rb;

    LOAD_AND_ATTACH_SKELETON(skel_sysstat, sysstat);

    if (env.part2) {
        printf("%-8s %-8s %-8s %-8s %-8s %-8s %-8s %-8s %-8s\n", "KRECLM", "SLAB", "SRECLM", "SUNRECL", "NFSUNSTB", "WRITEBACKTMP", "KMAP", "UNMAP", "PAGE");
    } else {
        printf("%-8s %-8s %-8s %-8s %-8s %-8s %-8s %-8s\n", "TIME", "PID", "CPU", "MEM", "READ", "WRITE", "IOWAIT", "SWAP");
    }
    POLL_RING_BUFFER(rb, 1000, err);

sysstat_cleanup:
	ring_buffer__free(rb);
	sysstat_bpf__destroy(skel_sysstat);
    return err;
}

static int process_memleak(struct memleak_bpf *skel_memleak, struct env env) {
	skel_memleak->rodata->stack_flags = env.kernel_trace ? KERN_STACKID_FLAGS : USER_STACKID_FLAGS;

	bpf_map__set_value_size(skel_memleak->maps.stack_traces, perf_max_stack_depth * sizeof(__u64));
	bpf_map__set_max_entries(skel_memleak->maps.stack_traces, stack_map_max_entries);

	if (!env.kernel_trace)
		disable_kernel_tracepoints(skel_memleak);

	int err = memleak_bpf__load(skel_memleak);
	if (err) {
		fprintf(stderr, "Failed to load BPF skeleton\n");
		goto memleak_cleanup;
	}

	if (!env.kernel_trace) {
		err = attach_uprobes(skel_memleak);
		if (err) {
			fprintf(stderr, "Failed to attach uprobes\n");
			goto memleak_cleanup;
		}
	}

	err = memleak_bpf__attach(skel_memleak);
	if (err) {
		fprintf(stderr, "Failed to auto-attach BPF skeleton: %d\n", err);
		goto memleak_cleanup;
	}

	g_stacks_size = perf_max_stack_depth * sizeof(*g_stacks);
	g_stacks = (__u64 *)malloc(g_stacks_size);
	if (!g_stacks) {
		fprintf(stderr, "Failed to allocate memory\n");
		err = -1;
		goto memleak_cleanup;
	}
	memset(g_stacks, 0, g_stacks_size);

	symbolizer = blaze_symbolizer_new();
	if (!symbolizer) {
		fprintf(stderr, "Fail to create a symbolizer\n");
		err = -1;
		goto memleak_cleanup;
	}

	for (;;) {
		if (!env.kernel_trace)
			if (env.print_time) {
				system("clear");
				update_addr_times(skel_memleak);
				print_time(skel_memleak);
			}
			else
				print_outstanding_combined_allocs(skel_memleak, attach_pid);
		else
			print_outstanding_allocs(skel_memleak);

		sleep(1);
	}

	while (!exiting) {
		/* Ctrl-C will cause -EINTR */
		if (err == -EINTR) {
			err = 0;
			break;
		}
		if (err < 0) {
			printf("Error polling perf buffer: %d\n", err);
			break;
		}
	}

memleak_cleanup:
	memleak_bpf__destroy(skel_memleak);
	if (symbolizer)
        blaze_symbolizer_free(symbolizer);
    if (g_stacks)
        free(g_stacks);
    if (allocs)
        free(allocs);
    return err;
}