/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */

/*
 * Minimal mem_monitor: Trace slab kmem_cache_alloc by process.
 * Simplified version without CLI args or fallback logic.
 */

#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "mem.h"
#include "mem_monitor.skel.h"
#include "trace_helpers.h"

#define warn(...) fprintf(stderr, __VA_ARGS__)
#define OUTPUT_ROWS_LIMIT 20

static volatile sig_atomic_t exiting = 0;

static void sig_int(int signo)
{
	exiting = 1;
}

int str_loadavg(char *buf, size_t buf_len)
{
	int n, err = 0;
	char avg[64] = {0};
	FILE *f;

	if (!buf || buf_len == 0)
		return -EINVAL;

	f = fopen("/proc/loadavg", "r");
	if (!f)
		return -errno;

	n = fread(avg, 1, sizeof(avg) - 1, f);
	if (!n) {
		err = -errno;
		goto cleanup;
	}

	n = snprintf(buf, buf_len, "loadavg: %s", avg);

	if (n >= buf_len)
		err = -ERANGE;

cleanup:
	fclose(f);
	return err ?: n;
}

int str_timestamp(const char *format, char *buf, size_t buf_len)
{
	time_t t;
	struct tm *tm;

	if (!format || !buf || buf_len == 0)
		return -EINVAL;

	time(&t);
	tm = localtime(&t);
	if (!tm)
		return -errno;
	return strftime(buf, buf_len, format, tm);
}

static int sort_column(const void *obj1, const void *obj2)
{
	const struct slabrate_info *s1 = obj1;
	const struct slabrate_info *s2 = obj2;
	return s2->size - s1->size; // 固定按 size 排序
}

static int print_stat(struct mem_monitor_bpf *obj)
{
	char loadavg[256], ts[64];
	char *key, **prev_key = NULL;
	static struct slabrate_info values[OUTPUT_ROWS_LIMIT];
	int i, err = 0, rows = 0;
	int fd = bpf_map__fd(obj->maps.slab_entries);

	err = str_loadavg(loadavg, sizeof(loadavg)) <= 0;
	err = err ?: (str_timestamp("%H:%M:%S", ts, sizeof(ts)) <= 0);
	if (!err)
		printf("%8s %s\n", ts, loadavg);

	printf("%-32s %6s %10s\n", "CACHE", "ALLOCS", "BYTES");

	while (1) {
		err = bpf_map_get_next_key(fd, prev_key, &key);
		if (err) {
			if (errno == ENOENT) {
				err = 0;
				break;
			}
			warn("bpf_map_get_next_key failed: %s\n", strerror(errno));
			return err;
		}
		err = bpf_map_lookup_elem(fd, &key, &values[rows++]);
		if (err) {
			warn("bpf_map_lookup_elem failed: %s\n", strerror(errno));
			return err;
		}
		prev_key = &key;
		if (rows >= OUTPUT_ROWS_LIMIT)
			break;
	}

	qsort(values, rows, sizeof(struct slabrate_info), sort_column);
	for (i = 0; i < rows; i++)
		printf("%-32s %6lld %10lld\n",
		       values[i].name, values[i].count, values[i].size);

	printf("\n");
	prev_key = NULL;

	while (1) {
		err = bpf_map_get_next_key(fd, prev_key, &key);
		if (err) {
			if (errno == ENOENT) {
				err = 0;
				break;
			}
			warn("bpf_map_get_next_key failed: %s\n", strerror(errno));
			return err;
		}
		err = bpf_map_delete_elem(fd, &key);
		if (err) {
			warn("bpf_map_delete_elem failed: %s\n", strerror(errno));
			return err;
		}
		prev_key = &key;
	}
	return err;
}

static int libbpf_print_fn(enum libbpf_print_level level,
			   const char *format, va_list args)
{
	if (level == LIBBPF_DEBUG)
		return 0; // 永远不打印 debug
	return vfprintf(stderr, format, args);
}

int main(int argc, char **argv)
{
	struct mem_monitor_bpf *obj;
	int err;

	libbpf_set_print(libbpf_print_fn);

	obj = mem_monitor_bpf__open();
	if (!obj) {
		warn("failed to open BPF object\n");
		return 1;
	}

	err = mem_monitor_bpf__load(obj);
	if (err) {
		warn("failed to load BPF object: %d\n", err);
		goto cleanup;
	}

	err = mem_monitor_bpf__attach(obj);
	if (err) {
		warn("failed to attach BPF programs: %d\n", err);
		goto cleanup;
	}

	if (signal(SIGINT, sig_int) == SIG_ERR) {
		warn("can't set signal handler: %s\n", strerror(errno));
		err = 1;
		goto cleanup;
	}

	while (!exiting) {
		sleep(1);
		system("clear");
		err = print_stat(obj);
		if (err)
			goto cleanup;
	}

cleanup:
	mem_monitor_bpf__destroy(obj);
	return err != 0;
}
