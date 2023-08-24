#ifndef _STACKFS_STATS_H__
#define _STACKFS_STATS_H__

#include <stdint.h>

struct lo_stats {
	uint64_t lookup;
	uint64_t getattr;
	uint64_t access;
	uint64_t readlink;
	uint64_t rename;
	uint64_t symlink;
	uint64_t link;
	uint64_t statfs;
	uint64_t setattr;
	uint64_t flush;
	uint64_t fsyncdir;
	uint64_t fsync;
	uint64_t forget;
	uint64_t forget_multi;
	uint64_t create;
	uint64_t open;
	uint64_t read;
	uint64_t write;
	uint64_t release;
	uint64_t unlink;
	uint64_t mkdir;
	uint64_t mknod;
	uint64_t rmdir;
	uint64_t opendir;
	uint64_t readdir;
	uint64_t releasedir;
#if	TESTING_XATTR
	uint64_t getxattr;
	uint64_t setxattr;
	uint64_t listxattr;
	uint64_t removexattr;
#endif
	uint64_t getlk;
	uint64_t setlk;
	uint64_t flock;
	uint64_t bmap;
	uint64_t ioctl;
	uint64_t poll;
	uint64_t fallocate;
#ifdef HAVE_UTIMENSAT
	uint64_t utimes;
#endif
};
#endif /* _STACKFS_STATS_H__ */
