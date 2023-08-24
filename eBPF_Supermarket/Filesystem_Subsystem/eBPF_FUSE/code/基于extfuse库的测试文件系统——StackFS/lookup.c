#define FUSE_USE_VERSION 30
#define _XOPEN_SOURCE 500
#define _GNU_SOURCE
#include <stdarg.h>
#include <unistd.h>
#include <stdio.h>
#include <pthread.h>
#include <time.h>
#include <stdint.h>
#include <inttypes.h>
#include <string.h>
#include <limits.h>
#include <stdlib.h>
#include <errno.h>
#include <fuse.h>
#include <linux/fuse.h>
#include <fuse_lowlevel.h>
#include <assert.h>
#include <stddef.h>
#include <fcntl.h> /* Definition of AT_* constants */
#include <sys/stat.h>
#include <sys/types.h>
#include <dirent.h>
#include <pthread.h>
#include <sys/xattr.h>
#include <sys/syscall.h>

#include "lookup.h"
#include "attr.h"

#define gettid getpid

#ifdef DEBUG
#define INFO(fmt, ...)  fprintf(stdout, fmt, ##__VA_ARGS__)
#else
#define INFO(fmt, ...)
#endif

#define ERROR(fmt, ...) fprintf(stderr, fmt, ##__VA_ARGS__)

static uint64_t num_entries;

static unsigned long calc_timeout_sec(double t)
{
    if (t > (double) ULONG_MAX)
        return ULONG_MAX;
    else if (t < 0.0)
        return 0;
    else
        return (unsigned long) t;
}

static unsigned int calc_timeout_nsec(double t)
{
    double f = t - (double) calc_timeout_sec(t);
    if (f < 0.0)
        return 0;
    else if (f >= 0.999999999)
        return 999999999;
    else
        return (unsigned int) (f * 1.0e9);
}

static void fill_entry(lookup_entry_val_t *arg,
               const struct fuse_entry_param *e)
{
	arg->nodeid = e->ino;
	arg->generation = e->generation;
	arg->entry_valid = calc_timeout_sec(e->entry_timeout);
	arg->entry_valid_nsec = calc_timeout_nsec(e->entry_timeout);
}

/*
 * Returns:
 *
 * zero  = no entry
 * -tive = stale entry
 * +tive = good
 */
int64_t lookup_fetch(ebpf_context_t *ctxt, uint64_t parent_ino,
		const char *name)
{
	int ret;
	lookup_entry_key_t key = {0, {0}};
	lookup_entry_val_t val = {0, 0, 0, 0, 0};

	// key
	key.nodeid = parent_ino;
	strncpy(key.name, name, NAME_MAX);

	INFO("[%d] \t Looking up node name %s (%ju) parent 0x%lx\n",
		gettid(), name, strlen(name), parent_ino);

	ret = ebpf_data_lookup(ctxt, (void *)&key, (void *)&val, 0);
	if (ret) {
		if (errno != ENOENT)
			ERROR("[%d] \t LOOKUP_FETCH node name %s(%ju) parent 0x%lx failed: %s\n",
				gettid(), name, strlen(name), parent_ino, strerror(errno));
		return ret;
	}

	if (val.stale) {
		INFO("[%d] \t Stale entry nlookup: %ld\n", gettid(), val.nlookup);
		val.nlookup *= -1;
	}

	errno = 0;
	return val.nlookup;
}

int lookup_insert(ebpf_context_t *ctxt, uint64_t parent_ino,
		const char *name, uint64_t nlookup, struct fuse_entry_param *e)
{
	// update attr
	int ret = attr_insert(ctxt, e->ino, &e->attr, e->attr_timeout);
	if (ret)
		return ret;

	lookup_entry_key_t key = {0, {0}};
	lookup_entry_val_t entry = {0, 0, 0, 0, 0};

	// key
	key.nodeid = parent_ino;
	strncpy(key.name, name, NAME_MAX);

	// entry value
	entry.nlookup = nlookup;
	fill_entry(&entry, e);

	INFO("[%d] \t Inserting node name %s (%ju) parent 0x%lx nlookup; %lu\n",
		gettid(), name, strlen(name), parent_ino, nlookup);

	// update entry
	int overwrite = 1; //XXX overwiting to update any negative entires
	ret = ebpf_data_update(ctxt, (void *)&key, (void *)&entry, 0, overwrite);
	if (ret)
		ERROR("[%d] \t Failed to insert %s (%ju) parent 0x%lx count %ju: %s\n",
			gettid(), name, strlen(name), parent_ino, num_entries, strerror(errno));
	else
		num_entries++;
	return ret;
}

void lookup_gc_stale(ebpf_context_t *ctxt)
{
	lookup_entry_key_t key = {0, {0}};
	lookup_entry_val_t val = {0, 0, 0, 0, 0};
	lookup_entry_key_t next_key = {0, {0}};

    while (ebpf_data_next(ctxt, (void *)&key, (void *)&next_key, 0) == 0) {
        ebpf_data_lookup(ctxt, (void *)&next_key, (void *)&val, 0);
        if (val.stale)
        	ebpf_data_delete(ctxt, (void *)&next_key, 0);
        key = next_key;
    }
}

int lookup_delete(ebpf_context_t *ctxt, uint64_t parent_ino,
		const char *name, uint64_t ino)
{
	// delete attr
	int ret = attr_delete(ctxt, ino);
	if (ret)
		return ret;

	// key
	lookup_entry_key_t key = {0, {0}};
	key.nodeid = parent_ino;
	strncpy(key.name, name, NAME_MAX);

	INFO("[%d] \t Deleting node name %s (%ju) parent 0x%lx\n",
		gettid(), name, strlen(name), parent_ino);

	// delete from lookup table
	ret = ebpf_data_delete(ctxt, (void *)&key, 0);
	if (ret && errno != ENOENT)
		ERROR("[%d] \t Failed to delete %s(%ju) parent 0x%lx count %ju: %s!\n",
			gettid(), name, strlen(name), parent_ino,
			num_entries, strerror(errno));
	else
		num_entries--;
	return ret;
}

#if 0
int lookup_rename(ebpf_context_t *ctxt, uint64_t old_pino,
			const char *oldname, uint64_t new_pino,
			const char *newname, uint64_t nlookup)
{
	int ret;
	lookup_entry_key_t key = {0, {0}};
	lookup_entry_val_t val = {0, 0, 0, 0, 0};

	// key
	key.nodeid = old_pino;
	strncpy(key.name, oldname, NAME_MAX);

	INFO("[%d] \t Looking up node oldname %s (%ju) old parent 0x%lx\n",
		gettid(), oldname, strlen(oldname), old_pino);

	ret = ebpf_data_lookup(ctxt, (void *)&key, (void *)&val);
	if (ret && errno != ENOENT) {
		ERROR("[%d] \t LOOKUP_RENAME node oldname %s(%ju) old parent 0x%lx "
			"failed: %s\n", gettid(), oldname, strlen(oldname),
			old_pino, strerror(errno));
		return ret;
	}

	INFO("[%d] \t Renaming node newname %s (%ju) new parent 0x%lx "
		"nlookup: %ld\n", gettid(), newname, strlen(newname),
		new_pino, val.nlookup);

	if (errno != ENOENT) {
		if (val.stale)
			ERROR("[%d] \t Renamed lookup node oldname %s(%ju) "
				"old parent 0x%lx val not stale!\n",
				gettid(), oldname, strlen(oldname), old_pino);

		// delete from lookup table
		ret = ebpf_data_delete(ctxt, (void *)&key);
		if (ret) {
			ERROR("[%d] \t Failed to delete %s (%ju) old parent 0x%lx "
				"count %ju: %s\n", gettid(), oldname, strlen(oldname), old_pino,
				num_entries, strerror(errno));
			return ret;
		}

		// use existing refcnt
		nlookup = val.nlookup;
	}

	// new key
	key.nodeid = new_pino;
	strncpy(key.name, newname, NAME_MAX);

	// fix node val
	val.nlookup = nlookup;

	INFO("[%d] \t Renaming node newname %s (%ju) new parent 0x%lx "
		"nlookup: %ld\n", gettid(), newname, strlen(newname),
		new_pino, val.nlookup);

	// update (overwrite) lookup table
	ret = ebpf_data_update(ctxt, (void *)&key, (void *)&val, 1);
	if (ret)
		ERROR("[%d] \t Failed to update %s (%ju) new parent 0x%lx: %s\n",
			gettid(), newname, strlen(newname), new_pino, strerror(errno));
	return ret;
}
#endif

void* lookup_init(struct fuse_conn_info *conn)
{
	return NULL;	
}

