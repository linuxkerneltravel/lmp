#ifndef _STACKFS_H__
#define _STACKFS_H__
#include <stdarg.h>
#include <unistd.h>
#include <stdio.h>

#ifdef ENABLE_EXTFUSE
#include <ebpf.h>
#endif


/* The node structure that we maintain as our local cache which maps
 * the ino numbers to their full path, this address is stored as part
 * of the value of the linked list of nodes */
struct lo_inode {

    struct lo_inode *next;  /* per-dir sibling list */
    struct lo_inode *child; /* first contained file by this dir */
    struct lo_inode *parent;    /* containing directory */

    /* Full path of the underlying ext4 path
     * correspoding to its ino (easy way to extract back) */
    char *name;
    unsigned int namelen;

    /* Inode numbers and dev no's of
     * underlying EXT4 F/s for the above path */
    ino_t ino;
    dev_t dev;

    /* inode number sent to lower F/S */
    ino_t lo_ino;
#ifdef ENABLE_EXTFUSE
	/* parent inode */
	ino_t pino;
#endif

	/* Lookup count of this node */
	uint64_t nlookup;

    /* Stats */
    int deleted;
};

/* The structure which is used to store the hash table
 * and it is always comes as part of the req structure */
struct lo_data {
    pthread_mutex_t mutex;
/* put the root Inode '/' here itself for faster
 * access and some other useful raesons */
    struct lo_inode root;
    /* do we still need this ? let's see*/
    double attr_valid;
	double entry_valid;
#ifdef ENABLE_EXTFUSE
	ebpf_context_t *ebpf_ctxt;
#endif
};

struct lo_dirptr {
	DIR *dp;
	struct dirent *entry;
	off_t offset;
};

struct stackFS_info {
	char	*root;
	char	*statsDir;/* Path to copy any statistics details */
	double	attr_valid;/* Time in secs for attribute validation */
	double entry_valid; /* Time in sec for entry validation */
	int	is_help;
	int	tracing;
};

#ifdef DEBUG
#define INFO(fmt, ...)	fprintf(stdout, fmt, ##__VA_ARGS__)
#else
#define INFO(fmt, ...)
#endif

#ifndef TRACE
#define generate_start_time(x)
#define generate_end_time(x)
#define fuse_session_add_statsDir(x,y)
#define fuse_session_remove_statsDir(x)
#define populate_time(x)
#endif

#define ERROR(fmt, ...)	fprintf(stderr, fmt, ##__VA_ARGS__)

#define STACKFS_OPT(t, p) { t, offsetof(struct stackFS_info, p), 1 }

static inline struct lo_dirptr *lo_dirptr(struct fuse_file_info *fi)
{
	return ((struct lo_dirptr *) ((uintptr_t) fi->fh));
}


static inline struct lo_data *get_lo_data(fuse_req_t req)
{
	return (struct lo_data *) fuse_req_userdata(req);
}

static inline struct lo_inode *lookup_node_by_id_locked(fuse_req_t req, fuse_ino_t ino)
{
    if (ino == FUSE_ROOT_ID)
        return &get_lo_data(req)->root;
    else
        return (struct lo_inode *) (uintptr_t) ino;
}

static inline void acquire_node_locked(struct lo_inode* inode)
{
    if (inode) {
        inode->nlookup++;
        //StackFS_trace("ACQUIRE %p (%s) rc=%ld\n", inode, inode->name, inode->refcount);
    } else {
        ERROR("acquire_node_locked: NULL inode\n");
    }
}

static inline double lo_attr_valid_time(fuse_req_t req)
{
	return get_lo_data(req)->attr_valid;
}

static inline double lo_entry_valid_time(fuse_req_t req)
{
	return get_lo_data(req)->entry_valid;
}

#endif
