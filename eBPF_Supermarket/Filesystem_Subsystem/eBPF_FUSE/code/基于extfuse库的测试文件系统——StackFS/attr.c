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

static void convert_stat(const struct stat *stbuf, struct fuse_attr *attr)
{
	attr->ino   = stbuf->st_ino;
	attr->mode  = stbuf->st_mode;
	attr->nlink = stbuf->st_nlink;
	attr->uid   = stbuf->st_uid;
	attr->gid   = stbuf->st_gid;
	attr->rdev  = stbuf->st_rdev;
	attr->size  = stbuf->st_size;
	attr->blksize   = stbuf->st_blksize;
	attr->blocks    = stbuf->st_blocks;
	attr->atime = stbuf->st_atime;
	attr->mtime = stbuf->st_mtime;
	attr->ctime = stbuf->st_ctime;
	attr->atimensec = ST_ATIM_NSEC(stbuf);
	attr->mtimensec = ST_MTIM_NSEC(stbuf);
	attr->ctimensec = ST_CTIM_NSEC(stbuf);
}

static void fill_attr(struct fuse_attr_out *arg,
				const struct stat *attr, double attr_timeout)
{
    memset(arg, 0, sizeof(*arg)); // XXX do not remove
    arg->attr_valid = calc_timeout_sec(attr_timeout);
    arg->attr_valid_nsec = calc_timeout_nsec(attr_timeout);
    convert_stat(attr, &arg->attr);
}

int attr_fetch(ebpf_context_t *ctxt, uint64_t nodeid,
			struct fuse_attr_out *out)
{
	int ret;
	lookup_attr_val_t val;

	INFO("[%d] \t Looking up attr for node 0x%lx\n", gettid(), nodeid);

	ret = ebpf_data_lookup(ctxt, (void *)&nodeid, (void *)&val, 1);
	if (ret) {
		if (errno != ENOENT)
			ERROR("[%d] \t ATTR_FETCH node 0x%lx failed: %s\n",
				gettid(), nodeid, strerror(errno));
		return ret;
	}

	errno = 0;
	memcpy((void *)out, (void *)&val.out, sizeof(*out));
	return 0;
}

int attr_insert(ebpf_context_t *ctxt, uint64_t nodeid,
				const struct stat *attr, double attr_timeout)
{
	int ret;
	lookup_attr_val_t val;

	val.stale = 0;

	// attr value
	fill_attr(&val.out, attr, attr_timeout);

	INFO("[%d] \t Inserting attr for node 0x%lx\n",
		gettid(), nodeid);

	// update lookup table
	int overwrite = 1; //XXX overwiting to update any negative entires

	ret = ebpf_data_update(ctxt, (void *)&nodeid, (void *)&val, 1, overwrite);
	if (ret)
		ERROR("[%d] \t Failed to insert attr for node 0x%lx count %ju: %s\n",
			gettid(), nodeid, num_entries, strerror(errno));
	else
		num_entries++;
	return ret;
}

int attr_delete(ebpf_context_t *ctxt, uint64_t nodeid)
{
	int ret;

	INFO("[%d] \t Deleting attr for node 0x%lx\n", gettid(), nodeid);

	// delete from lookup table
	ret = ebpf_data_delete(ctxt, (void *)&nodeid, 1);
	if (ret && errno != ENOENT)
		ERROR("[%d] \t Failed to delete attr for node 0x%lx count %ju: %s!\n",
			gettid(), nodeid, num_entries, strerror(errno));
	else
		num_entries--;
	return ret;
}

void* attr_init(struct fuse_conn_info *conn)
{
    return NULL;    
}
