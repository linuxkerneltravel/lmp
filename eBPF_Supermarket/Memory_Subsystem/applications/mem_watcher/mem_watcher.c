
#include <argp.h>
#include <signal.h>
#include <stdio.h>
#include <time.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include <sys/select.h>
#include <unistd.h>
#include "mem_watcher.h"
#include "paf.h"
#include "paf.skel.h"
#include "pr.h"
#include "pr.skel.h"
#include "procstat.h"
#include "procstat.skel.h"
#include "sysstat.h"
#include "sysstat.skel.h"

#define PAF 0
#define PR 0
#define PROCSTAT 0
#define SYSSTAT 1

pid_t own_pid;

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	return vfprintf(stderr, format, args);
}

static volatile bool exiting;

static void sig_handler(int sig)
{
	exiting = true;
}

static int paf_handle_event(void *ctx, void *data, size_t data_sz)
{
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

static int pr_handle_event(void *ctx, void *data, size_t data_sz)
{
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

static int procstat_handle_event(void *ctx, void *data, size_t data_sz)
{
	const struct procstat_event *e = data;
	struct tm *tm;
	char ts[32];
	time_t t;

	time(&t);
	tm = localtime(&t);
	strftime(ts, sizeof(ts), "%H:%M:%S", tm);

	printf("%-8s %-8d %-8ld %-8lld %-8lld %-8lld\n", ts, e->pid, e->size, e->rssanon, e->rssfile, e->rssshmem);
	return 0;
}

static int sysstat_handle_event(void *ctx, void *data, size_t data_sz)
{
	const struct sysstat_event *e = data;
	struct tm *tm;
	char ts[32];
	time_t t;

	time(&t);
	tm = localtime(&t);
	strftime(ts, sizeof(ts), "%H:%M:%S", tm);

	printf("%-8lu %-8lu %-8lu %-8lu %-8lu %-8lu %-8lu----- %-8lu %-8lu %-8lu %-8lu %-8lu----- %-8lu %-8lu %-8lu %-8lu--- %-8lu %-8lu %-8lu %-8lu %-8lu\n",
		   e->anon_active + e->file_active, e->file_inactive + e->anon_inactive, e->anon_active, e->anon_inactive, e->file_active, e->file_inactive, e->unevictable, e->file_dirty, e->writeback, e->anon_mapped, e->file_mapped, e->shmem, e->slab_reclaimable + e->kernel_misc_reclaimable, e->slab_reclaimable + e->slab_unreclaimable, e->slab_reclaimable, e->slab_unreclaimable, e->unstable_nfs, e->writeback_temp, e->anon_thps, e->shmem_thps, e->pmdmapped);
	return 0;
}

int main(int argc, char **argv)
{
	struct ring_buffer *rb = NULL;
	struct paf_bpf *skel;
	int err;

	own_pid = getpid();

	libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
	/* Set up libbpf errors and debug info callback */
	libbpf_set_print(libbpf_print_fn);

	/* Cleaner handling of Ctrl-C */
	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);

	if (PAF)
	{
		/* Load and verify BPF application */
		skel = paf_bpf__open();
		if (!skel)
		{
			fprintf(stderr, "Failed to open and load BPF skeleton\n");
			return 1;
		}

		skel->bss->user_pid = own_pid;

		/* Load & verify BPF programs */
		err = paf_bpf__load(skel);
		if (err)
		{
			fprintf(stderr, "Failed to load and verify BPF skeleton\n");
			goto paf_cleanup;
		}

		/* Attach tracepoints */
		err = paf_bpf__attach(skel);
		if (err)
		{
			fprintf(stderr, "Failed to attach BPF skeleton\n");
			goto paf_cleanup;
		}

		/* Set up ring buffer polling */
		rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), paf_handle_event, NULL, NULL);
		if (!rb)
		{
			err = -1;
			fprintf(stderr, "Failed to create ring buffer\n");
			goto paf_cleanup;
		}
		/* Process events */
		printf("%-8s %-8s %-8s %-8s %-8s %-8s\n", "TIME", "PID", "SIZE", "RSSANON", "RSSFILE", "RSSSHMEM");
	}
	else if (PR)
	{
		/* Load and verify BPF application */
		skel = pr_bpf__open();
		if (!skel)
		{
			fprintf(stderr, "Failed to open and load BPF skeleton\n");
			return 1;
		}

		skel->bss->user_pid = own_pid;

		/* Load & verify BPF programs */
		err = pr_bpf__load(skel);
		if (err)
		{
			fprintf(stderr, "Failed to load and verify BPF skeleton\n");
			goto pr_cleanup;
		}

		/* Attach tracepoints */
		err = pr_bpf__attach(skel);
		if (err)
		{
			fprintf(stderr, "Failed to attach BPF skeleton\n");
			goto pr_cleanup;
		}

		/* Set up ring buffer polling */
		rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), pr_handle_event, NULL, NULL);
		if (!rb)
		{
			err = -1;
			fprintf(stderr, "Failed to create ring buffer\n");
			goto pr_cleanup;
		}

		/* Process events */
		printf("%-8s %-8s %-8s %-8s %-8s\n", "RECLAIM", "RECLAIMED", "UNQUEUE", "CONGESTED", "WRITEBACK");
	}
	else if (PROCSTAT)
	{
		/* Load and verify BPF application */
		skel = procstat_bpf__open();
		if (!skel)
		{
			fprintf(stderr, "Failed to open and load BPF skeleton\n");
			return 1;
		}

		skel->bss->user_pid = own_pid;

		/* Load & verify BPF programs */
		err = procstat_bpf__load(skel);
		if (err)
		{
			fprintf(stderr, "Failed to load and verify BPF skeleton\n");
			goto procstat_cleanup;
		}

		/* Attach tracepoints */
		err = procstat_bpf__attach(skel);
		if (err)
		{
			fprintf(stderr, "Failed to attach BPF skeleton\n");
			goto procstat_cleanup;
		}

		/* Set up ring buffer polling */
		rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), procstat_handle_event, NULL, NULL);
		if (!rb)
		{
			err = -1;
			fprintf(stderr, "Failed to create ring buffer\n");
			goto procstat_cleanup;
		}
		printf("%-8s %-8s %-8s %-8s %-8s %-8s\n", "TIME", "PID", "SIZE", "RSSANON", "RSSFILE", "RSSSHMEM");
	}
	else if (SYSSTAT)
	{
		/* Load and verify BPF application */
		skel = sysstat_bpf__open();
		if (!skel)
		{
			fprintf(stderr, "Failed to open and load BPF skeleton\n");
			return 1;
		}

		skel->bss->user_pid = own_pid;

		/* Load & verify BPF programs */
		err = sysstat_bpf__load(skel);
		if (err)
		{
			fprintf(stderr, "Failed to load and verify BPF skeleton\n");
			goto sysstat_cleanup;
		}

		/* Attach tracepoints */
		err = sysstat_bpf__attach(skel);
		if (err)
		{
			fprintf(stderr, "Failed to attach BPF skeleton\n");
			goto sysstat_cleanup;
		}

		/* Set up ring buffer polling */
		rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), sysstat_handle_event, NULL, NULL);
		if (!rb)
		{
			err = -1;
			fprintf(stderr, "Failed to create ring buffer\n");
			goto sysstat_cleanup;
		}
		printf("%-8s %-8s %-8s %-8s %-8s %-8s\n", "TIME", "PID", "SIZE", "RSSANON", "RSSFILE", "RSSSHMEM");
	}

	while (!exiting)
	{
		err = ring_buffer__poll(rb, 100 /* timeout, ms */);
		/* Ctrl-C will cause -EINTR */
		if (err == -EINTR)
		{
			err = 0;
			break;
		}
		if (err < 0)
		{
			printf("Error polling perf buffer: %d\n", err);
			break;
		}
	}

paf_cleanup:
	ring_buffer__free(rb);
	paf_bpf__destroy(skel);
	return err < 0 ? -err : 0;

pr_cleanup:
	ring_buffer__free(rb);
	pr_bpf__destroy(skel);
	return err < 0 ? -err : 0;

procstat_cleanup:
	ring_buffer__free(rb);
	procstat_bpf__destroy(skel);
	return err < 0 ? -err : 0;

sysstat_cleanup:
	ring_buffer__free(rb);
	sysstat_bpf__destroy(skel);
	return err < 0 ? -err : 0;
}
