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

static struct blaze_symbolizer *symbolizer;

static int attach_pid;
static char binary_path[128] = {0};
 
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


static struct env {
	int time;
	bool paf;
	bool pr;
	bool procstat;
	bool sysstat;
	bool memleak;

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
	.rss = false,
	.part2 = false,
};

const char argp_program_doc[] = "mem_watcher is in use ....\n";

static const struct argp_option opts[] = {
	{0, 0, 0, 0, "select function:", 1},

	{"paf", 'a', 0, 0, "print paf (内存页面状态报告)", 2},

	{"pr", 'p', 0, 0, "print pr (页面回收状态报告)", 3},

	{"procstat", 'r', 0, 0, "print procstat (进程内存状态报告)", 4},
	{0, 0, 0, 0, "procstat additional function:"},
	{"choose_pid", 'P', "PID", 0, "选择进程号打印"},
	{"Rss", 'R', NULL, 0, "打印进程页面", 5},

	{"sysstat", 's', 0, 0, "print sysstat (系统内存状态报告)", 6},
	{0, 0, 0, 0, "sysstat additional function:"},
	{"part2", 'n', NULL, 0, "系统内存状态报告2", 7},

	{"memleak", 'l', "PID", 0, "print memleak (内存泄漏检测)", 8},

	{"time", 't', "TIME-SEC", 0, "Max Running Time(0 for infinite)", 9},
	{NULL, 'h', NULL, OPTION_HIDDEN, "show the full help"},
	{0},
};

static error_t parse_arg(int key, char *arg, struct argp_state *state) {
	switch (key) {
	case 't':
		env.time = strtol(arg, NULL, 10);
		if (env.time)
			alarm(env.time);
		break;
	case 'a':
		env.paf = true;
		break;
	case 'p':
		env.pr = true;
		break;
	case 'r':
		env.procstat = true;
		break;
	case 's':
		env.sysstat = true;
		break;
	case 'n':
		env.part2 = true;
		break;
	case 'h':
		argp_state_help(state, stderr, ARGP_HELP_STD_HELP);
		break;
	case 'P':
		env.choose_pid = strtol(arg, NULL, 10);
		break;
	case 'R':
		env.rss = true;
		break;
	case 'l':
		env.memleak = true;
		break;
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

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args) {
	return vfprintf(stderr, format, args);
}

static volatile bool exiting = false;

static void sig_handler(int sig) {
	exiting = true;
	exit(EXIT_SUCCESS); 
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

pid_t own_pid;

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

int main(int argc, char **argv) {
	struct ring_buffer *rb = NULL;
	struct paf_bpf *skel_paf;
	struct pr_bpf *skel_pr;
	struct procstat_bpf *skel_procstat;
	struct sysstat_bpf *skel_sysstat;
	struct memleak_bpf *skel;

	int err, i;
	LIBBPF_OPTS(bpf_uprobe_opts, uprobe_opts);

	err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (err)
		return err;
	own_pid = getpid();
	libbpf_set_strict_mode(LIBBPF_STRICT_ALL);

	/* Set up libbpf errors and debug info callback */
	libbpf_set_print(libbpf_print_fn);

	/* Cleaner handling of Ctrl-C */
	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);
	signal(SIGALRM, sig_handler);

	if (env.paf) {
		/* Load and verify BPF application */
		skel_paf = paf_bpf__open();
		if (!skel_paf) {
			fprintf(stderr, "Failed to open and load BPF skeleton\n");
			return 1;
		}

		skel_paf->bss->user_pid = own_pid;

		/* Load & verify BPF programs */
		err = paf_bpf__load(skel_paf);
		if (err) {
			fprintf(stderr, "Failed to load and verify BPF skeleton\n");
			goto paf_cleanup;
		}

		/* Attach tracepoints */
		err = paf_bpf__attach(skel_paf);
		if (err) {
			fprintf(stderr, "Failed to attach BPF skeleton\n");
			goto paf_cleanup;
		}

		/* Set up ring buffer polling */
		rb = ring_buffer__new(bpf_map__fd(skel_paf->maps.rb), handle_event_paf, NULL, NULL);
		if (!rb) {
			err = -1;
			fprintf(stderr, "Failed to create ring buffer\n");
			goto paf_cleanup;
		}

		/* Process events */
		printf("%-8s %-8s  %-8s %-8s %-8s\n", "MIN", "LOW", "HIGH", "PRESENT", "FLAG");
	}
	else if (env.pr) {
		/* Load and verify BPF application */
		skel_pr = pr_bpf__open();
		if (!skel_pr) {
			fprintf(stderr, "Failed to open and load BPF skeleton\n");
			return 1;
		}

		skel_pr->bss->user_pid = own_pid;

		/* Load & verify BPF programs */
		err = pr_bpf__load(skel_pr);
		if (err) {
			fprintf(stderr, "Failed to load and verify BPF skeleton\n");
			goto pr_cleanup;
		}

		/* Attach tracepoints */
		err = pr_bpf__attach(skel_pr);
		if (err) {
			fprintf(stderr, "Failed to attach BPF skeleton\n");
			goto pr_cleanup;
		}

		/* Set up ring buffer polling */
		rb = ring_buffer__new(bpf_map__fd(skel_pr->maps.rb), handle_event_pr, NULL, NULL);
		if (!rb) {
			err = -1;
			fprintf(stderr, "Failed to create ring buffer\n");
			goto pr_cleanup;
		}

		/* Process events */
		printf("%-8s %-8s %-8s %-8s %-8s\n", "RECLAIM", "RECLAIMED", "UNQUEUE", "CONGESTED", "WRITEBACK");
	}

	else if (env.procstat) {
		/* Load and verify BPF application */
		skel_procstat = procstat_bpf__open();
		if (!skel_procstat) {
			fprintf(stderr, "Failed to open and load BPF skeleton\n");
			return 1;
		}

		skel_procstat->bss->user_pid = own_pid;

		/* Load & verify BPF programs */
		err = procstat_bpf__load(skel_procstat);
		if (err) {
			fprintf(stderr, "Failed to load and verify BPF skeleton\n");
			goto procstat_cleanup;
		}

		/* Attach tracepoints */
		err = procstat_bpf__attach(skel_procstat);
		if (err) {
			fprintf(stderr, "Failed to attach BPF skeleton\n");
			goto procstat_cleanup;
		}

		/* Set up ring buffer polling */
		rb = ring_buffer__new(bpf_map__fd(skel_procstat->maps.rb), handle_event_procstat, NULL, NULL);
		if (!rb) {
			err = -1;
			fprintf(stderr, "Failed to create ring buffer\n");
			goto procstat_cleanup;
		}

		/* Process events */
		if (env.rss == true) {
			printf("%-8s %-8s %-8s %-8s %-8s %-8s %-8s\n", "TIME", "PID", "VMSIZE", "VMDATA", "VMSTK", "VMPTE", "VMSWAP");
		}
		else {
			printf("%-8s %-8s %-8s %-8s %-8s %-8s\n", "TIME", "PID", "SIZE", "RSSANON", "RSSFILE", "RSSSHMEM");
		}
	}

	else if (env.sysstat) {
		/* Load and verify BPF application */
		skel_sysstat = sysstat_bpf__open();
		if (!skel_sysstat) {
			fprintf(stderr, "Failed to open and load BPF skeleton\n");
			return 1;
		}

		skel_sysstat->bss->user_pid = own_pid;

		/* Load & verify BPF programs */
		err = sysstat_bpf__load(skel_sysstat);
		if (err) {
			fprintf(stderr, "Failed to load and verify BPF skeleton\n");
			goto sysstat_cleanup;
		}

		/* Attach tracepoints */
		err = sysstat_bpf__attach(skel_sysstat);
		if (err) {
			fprintf(stderr, "Failed to attach BPF skeleton\n");
			goto sysstat_cleanup;
		}

		/* Set up ring buffer polling */
		rb = ring_buffer__new(bpf_map__fd(skel_sysstat->maps.rb), handle_event_sysstat, NULL, NULL);
		if (!rb) {
			err = -1;
			fprintf(stderr, "Failed to create ring buffer\n");
			goto sysstat_cleanup;
		}

		/* Process events */
		if (env.part2 == true) {
			printf("%-8s %-8s %-8s %-8s %-8s %-8s %-8s %-8s %-8s\n", "KRECLM", "SLAB", "SRECLM", "SUNRECLMA", "UNSTABLE", "WRITEBK_T", "ANONHUGE", "SHMEMHUGE", "PMDMAPP");
		}
		else {
			printf("%-8s %-8s %-8s %-8s %-8s %-8s %-8s %-8s %-8s %-8s %-8s %-8s\n", "ACTIVE", "INACTVE", "ANON_ACT", "ANON_INA", "FILE_ACT", "FILE_INA", "UNEVICT", "DIRTY", "WRITEBK", "ANONPAG", "MAP", "SHMEM");
		}
	}

	else if (env.memleak) {
		if (argc != 3) {
			printf("usage:%s attach_pid\n", argv[0]);
			return -1;
		}

		attach_pid = atoi(argv[2]);

		strcpy(binary_path, "/lib/x86_64-linux-gnu/libc.so.6");

		/* Set up libbpf errors and debug info callback */
		libbpf_set_print(libbpf_print_fn);

		/* Load and verify BPF application */
		skel = memleak_bpf__open();
		if (!skel) {
			fprintf(stderr, "Failed to open BPF skeleton\n");
			return 1;
		}

		bpf_map__set_value_size(skel->maps.stack_traces, perf_max_stack_depth * sizeof(__u64));
		bpf_map__set_max_entries(skel->maps.stack_traces, stack_map_max_entries);

		/* Load & verify BPF programs */
		err = memleak_bpf__load(skel);
		if (err) {
			fprintf(stderr, "Failed to load BPF skeleton\n");
			goto memleak_cleanup;
		}

		err = attach_uprobes(skel);
		if (err) {
			fprintf(stderr, "failed to attach uprobes\n");
			goto memleak_cleanup;
		}

		/* Let libbpf perform auto-attach for uprobe_sub/uretprobe_sub
		 * NOTICE: we provide path and symbol info in SEC for BPF programs
		 */
		err = memleak_bpf__attach(skel);
		if (err) {
			fprintf(stderr, "Failed to auto-attach BPF skeleton: %d\n", err);
			goto memleak_cleanup;
		}

		g_stacks_size = perf_max_stack_depth * sizeof(*g_stacks);
		g_stacks = (__u64 *)malloc(g_stacks_size);
		memset(g_stacks, 0, g_stacks_size);

		symbolizer = blaze_symbolizer_new();
		if (!symbolizer) {
			fprintf(stderr, "Fail to create a symbolizer\n");
			err = -1;
			goto memleak_cleanup;
		}

		for (i = 0;; i++) {
			/* trigger our BPF programs */
			print_outstanding_combined_allocs(skel, attach_pid);
			sleep(1);
		}
	}

	while (!exiting) {
		if (env.paf || env.pr || env.procstat || env.sysstat) {
			err = ring_buffer__poll(rb, 1000 /* timeout, ms */);
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
		else if (env.memleak) {
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
		else {
			printf("请输入要使用的功能...\n");
			break;
		}
	}

paf_cleanup:
	ring_buffer__free(rb);
	paf_bpf__destroy(skel_paf);
	return err < 0 ? -err : 0;

pr_cleanup:
	ring_buffer__free(rb);
	pr_bpf__destroy(skel_pr);
	return err < 0 ? -err : 0;

procstat_cleanup:
	ring_buffer__free(rb);
	procstat_bpf__destroy(skel_procstat);
	return err < 0 ? -err : 0;

sysstat_cleanup:
	ring_buffer__free(rb);
	sysstat_bpf__destroy(skel_sysstat);
	return err < 0 ? -err : 0;

memleak_cleanup:
	memleak_bpf__destroy(skel);
	blaze_symbolizer_free(symbolizer);
	free(g_stacks);
	return err < 0 ? -err : 0;
}