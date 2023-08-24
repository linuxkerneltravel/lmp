#ifndef __LOOKUP_H__
#define __LOOKUP_H__

#define FUSE_USE_VERSION 30
#define _GNU_SOURCE

#include <stdarg.h>
#include <unistd.h>
#include <stdio.h>

#include <fuse.h>
#include <linux/fuse.h>
#include <fuse_lowlevel.h>

#include <ebpf.h>
#include <bpf/lookup.h>

void *lookup_init(struct fuse_conn_info *conn);
int lookup_insert(ebpf_context_t *ctxt, uint64_t pino, const char *name,
		uint64_t nlookup, struct fuse_entry_param *e);
void lookup_gc_stale(ebpf_context_t *ctxt);
int lookup_delete(ebpf_context_t *ctxt, uint64_t pino, const char *name, uint64_t ino);
int64_t lookup_fetch(ebpf_context_t *ctxt, uint64_t pino, const char *name);
int lookup_rename(ebpf_context_t *ctxt, uint64_t old_pino,
			const char *oldname, uint64_t new_pino,
			const char *newname, uint64_t nlookup);
#endif
