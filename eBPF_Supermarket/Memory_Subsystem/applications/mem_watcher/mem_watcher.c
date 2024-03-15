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

#include <argp.h>
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
#include "mem_watcher.h"

static struct env {
	int time;
	bool paf;
	bool pr;
	bool procstat;
	bool sysstat;

	bool part2;

	long choose_pid;
	bool rss;
} env = {
	.time = 0,
	.paf = false,
	.pr = false,
	.procstat = false,
	.sysstat = false,
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

	{"time", 't', "TIME-SEC", 0, "Max Running Time(0 for infinite)", 8},
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

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args) {
	return vfprintf(stderr, format, args);
}

static volatile bool exiting = false;

static void sig_handler(int sig) {
	exiting = true;
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

int main(int argc, char **argv) {
	struct ring_buffer *rb = NULL;
	struct paf_bpf *skel_paf;
	struct pr_bpf *skel_pr;
	struct procstat_bpf *skel_procstat;
	struct sysstat_bpf *skel_sysstat;

	int err;
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

	while (!exiting) {
		if (env.paf) {
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
		else if (env.pr) {
			err = ring_buffer__poll(rb, 100 /* timeout, ms */);
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
		else if (env.procstat) {
			err = ring_buffer__poll(rb, 100 /* timeout, ms */);
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
		else if (env.sysstat) {
			err = ring_buffer__poll(rb, 100 /* timeout, ms */);
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
}