/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Userspace component for the scx_contention scheduler.
 *
 * This program loads the scx_contention BPF scheduler, attaches it,
 * and provides a user interface to monitor its state and statistics.
 * It can also configure tunable parameters of the scheduler.
 *
 * Copyright (c) 2024 Your Name <your.email@example.com>
 * Based on scx_simple by Meta Platforms, Inc. and affiliates.
 */
#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <libgen.h>
#include <bpf/bpf.h>
#include <scx/common.h>
#include "scx_contention.bpf.skel.h"

// 和 BPF 代码中定义一致
struct contention_info {
    u32 waiter_count;
    u64 last_contention_ts;
};

const char help_fmt[] =
"A contention-aware sched_ext scheduler.\n"
"\n"
"See the top-level comment in .bpf.c for more details.\n"
"\n"
"Usage: %s [-f] [-v] [-t threshold] [-d decay_ms]\n"
"\n"
"  -f            Use FIFO scheduling instead of weighted vtime scheduling\n"
"  -t <count>    Set the high contention threshold (default: 4 waiters)\n"
"  -d <ms>       Set the priority decay timeout in milliseconds (default: 200ms)\n"
"  -v            Print libbpf debug messages\n"
"  -h            Display this help and exit\n";

static bool verbose;
static volatile int exit_req;

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args) {
	if (level == LIBBPF_DEBUG && !verbose)
		return 0;
	return vfprintf(stderr, format, args);
}

static void sigint_handler(int sig) {
	exit_req = 1;
}

static void read_stats(struct scx_contention *skel, __u64 *stats) {
	int nr_cpus = libbpf_num_possible_cpus();
	__u64 cnts[2][nr_cpus];
	__u32 idx;

	memset(stats, 0, sizeof(stats[0]) * 2);

	for (idx = 0; idx < 2; idx++) {
		int ret, cpu;
		ret = bpf_map_lookup_elem(bpf_map__fd(skel->maps.stats), &idx, cnts[idx]);
		if (ret < 0) continue;
		for (cpu = 0; cpu < nr_cpus; cpu++)
			stats[idx] += cnts[idx][cpu];
	}
}

// 新增函数：打印正在被提权的竞争任务
static void print_contended_tasks(struct scx_contention *skel) {
    int map_fd = bpf_map__fd(skel->maps.contended_tasks);
    __u32 key = 0, prev_key;
    struct contention_info info;

    printf("--- Contended Tasks (Boosted) ---\n");
    while (bpf_map_get_next_key(map_fd, &prev_key, &key) == 0) {
        if (bpf_map_lookup_elem(map_fd, &key, &info) == 0) {
            printf("  Owner TID: %-7u | Waiters: %-3u\n", key, info.waiter_count);
        }
        prev_key = key;
    }
    printf("---------------------------------\n");
}


int main(int argc, char **argv) {
	struct scx_contention *skel;
	struct bpf_link *link;
	int opt;
	__u64 ecode;

	libbpf_set_print(libbpf_print_fn);
	signal(SIGINT, sigint_handler);
	signal(SIGTERM, sigint_handler);

restart:
	skel = SCX_OPS_OPEN(contention_ops, scx_contention);
    if (!skel) SCX_BUG("Failed to open BPF skeleton");

	while ((opt = getopt(argc, argv, "fvt:d:h")) != -1) {
		switch (opt) {
		case 'f':
			skel->rodata->fifo_sched = true;
			break;
		case 'v':
			verbose = true;
			break;
        case 't':
            skel->rodata->high_contention_threshold = atoi(optarg);
            break;
        case 'd':
            skel->rodata->decay_timeout_ns = (__u64)atoi(optarg) * 1000 * 1000;
            break;
		default:
			fprintf(stderr, help_fmt, basename(argv[0]));
			return opt != 'h';
		}
	}

	SCX_OPS_LOAD(skel, contention_ops, scx_contention, uei);
	link = SCX_OPS_ATTACH(skel, contention_ops, scx_contention);
    if (!link) SCX_BUG("Failed to attach BPF program");

    printf("scx_contention scheduler attached. Monitoring lock contention...\n");

	while (!exit_req && !UEI_EXITED(skel, uei)) {
		__u64 stats[2];

        // 清屏，为了更好的显示效果
        printf("\033[2J\033[H");

		read_stats(skel, stats);
		printf("local q=%-10llu | global q=%-10llu\n\n", stats[0], stats[1]);
        
        print_contended_tasks(skel);

		fflush(stdout);
		sleep(1);
	}

	bpf_link__destroy(link);
	ecode = UEI_REPORT(skel, uei);
	scx_contention__destroy(skel);

	if (UEI_ECODE_RESTART(ecode))
		goto restart;
	return 0;
}