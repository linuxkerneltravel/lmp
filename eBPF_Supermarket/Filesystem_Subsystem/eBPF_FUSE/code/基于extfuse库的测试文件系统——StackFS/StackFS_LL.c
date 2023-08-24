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
#include <assert.h>
#include <fuse_lowlevel.h>
#include <stddef.h>
#include <fcntl.h> /* Definition of AT_* constants */
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/types.h>
#include <dirent.h>
#include <pthread.h>
#include <sys/xattr.h>
#include <sys/syscall.h>
#include <sys/types.h>

#define gettid getpid

#ifdef ENABLE_EXTFUSE_LOOKUP
#include "lookup.h"
#ifndef ENABLE_EXTFUSE_ATTR
#define ENABLE_EXTFUSE_ATTR
#endif
#endif

#ifdef ENABLE_EXTFUSE_ATTR
#include "attr.h"
#endif

#include "StackFS_LL.h"

#define HAVE_XATTR 1

#ifdef CACHE_ENTRY_ATTR
#define BIG_TIMEOUT 99999999.0
#endif

pthread_mutex_t mutex; /* Protecting the above mutex lock */

#ifdef ENABLE_EXTFUSE
static int rootfd = -1;
#endif

#ifdef ENABLE_STATS
#include "stats.h"
#include <sys/signal.h>
#include <sys/ucontext.h>
#define USER_STATS_FILE "/tmp/user_stats.txt"
static struct sigaction old;
static int stats_fd = -1;
static struct lo_stats stats;
#define INCR_COUNTER(x) stats.x++
#else
#define INCR_COUNTER(x)
#endif

void print_usage(void)
{
	INFO("USAGE	: ./StackFS_ll -r <root>|-rootdir=<root> ");
	INFO("<mntpnt> [FUSE options]\n");
	INFO("<root>  : Root Directory containg the Low Level F/S\n");
	INFO("<mntpnt> : Mount point ");
	INFO("Example    : ./StackFS_ll -r root/ mntpnt/\n");
}

int64_t print_timer(void)
{
	struct timespec tms;

	if (clock_gettime(CLOCK_REALTIME, &tms)) {
		INFO("ERROR\n");
		return 0;
	}
	int64_t micros = tms.tv_sec * 1000000;

	micros += tms.tv_nsec/1000;
	if (tms.tv_nsec % 1000 >= 500)
		++micros;
	return micros;
}

static void remove_node_from_parent_locked(fuse_req_t req, struct lo_inode* inode);

static void release_node_locked(fuse_req_t req, struct lo_inode* inode)
{
    INFO("[%d] \t RELEASE %p (%s) nlookup: %ld\n",
		gettid(), inode, inode->name, inode->nlookup);
    if (inode->nlookup > 0) {
        inode->nlookup--;
        if (!inode->nlookup) {
#ifdef ENABLE_EXTFUSE_LOOKUP
			int res = lookup_delete(get_lo_data(req)->ebpf_ctxt, inode->pino,
							inode->name, inode->lo_ino);
			if (res && errno != ENOENT) {
				ERROR("Failed to delete node %s parent 0x%lx from hashtab\n",
					inode->name, inode->pino);
			}
#endif
            INFO("[%d] \t REMOVE NODE FROM PARENT %p (%s)\n",
				gettid(), inode, inode->name);
            remove_node_from_parent_locked(req, inode);
            INFO("[%d] \t FREE %p (%s)\n",
				gettid(), inode, inode->name);
            /* TODO: remove debugging - poison memory */
            memset(inode->name, 0xef, inode->namelen);
            free(inode->name);
            memset(inode, 0xfc, sizeof(*inode));
            free(inode);
        }
    } else {
        ERROR("Zero refcnt %p (%s)\n", inode, inode->name);
    }
}

static void add_node_to_parent_locked(struct lo_inode *inode, struct lo_inode *parent) {
    if (inode && parent) {
        inode->parent = parent;
        inode->next = parent->child;
        parent->child = inode;
        acquire_node_locked(parent);
    } else
        ERROR("add_node_to_parent_locked: NULL inode or parent\n");
}

static void remove_node_from_parent_locked(fuse_req_t req, struct lo_inode* inode)
{
    if (inode->parent) {
        if (inode->parent->child == inode) {
            inode->parent->child = inode->parent->child->next;
        } else {
            struct lo_inode *inode2;
            inode2 = inode->parent->child;
            while (inode2 && inode2->next && inode2->next != inode) {
                inode2 = inode2->next;
			}
            inode2->next = inode->next;
        }
        release_node_locked(req, inode->parent);
        inode->parent = NULL;
        inode->next = NULL;
    }
}

/* Gets the absolute path to a node into the provided buffer.
 *
 * Populates 'buf' with the path and returns the length of the path on success,
 * or returns -1 if the path is too long for the provided buffer.
 */
static ssize_t get_node_path_locked(struct lo_inode* inode, char* buf, size_t bufsize) {
    const char *name = inode->name;
    size_t namelen = inode->namelen;

    if (bufsize < namelen + 1) {
        ERROR("Failed to get path for node %s: bufsize (%ju) < namelen (%ju)\n",
			name, bufsize, namelen);
        return -1;
    }

    ssize_t pathlen = 0;
    if (inode->parent) {
        pathlen = get_node_path_locked(inode->parent, buf, bufsize - namelen - 1);
        if (pathlen < 0) {
            ERROR("Failed to get path for parent of node %s\n", name);
            return -1;
        }
        buf[pathlen++] = '/';
    }

    memcpy(buf + pathlen, name, namelen + 1); /* include trailing \0 */

    //INFO("Getting path for node %s(%d): %s(%d)\n",
    //              name, namelen, buf, pathlen + namelen);
    return pathlen + namelen;
}

static struct lo_inode* lookup_node_and_path_by_id_locked(fuse_req_t req,
                                    fuse_ino_t ino, char* buf, size_t bufsize)
{
    struct lo_inode* inode = lookup_node_by_id_locked(req, ino);
    if (inode && get_node_path_locked(inode, buf, bufsize) < 0) {
        inode = NULL;
    }
    return inode;
}

static struct lo_inode *lookup_child_by_name_locked(struct lo_inode *inode, const char *name)
{
    for (inode = inode->child; inode; inode = inode->next) {
        /* use exact string comparison, nodes that differ by case
         * must be considered distinct even if they refer to the same
         * underlying file as otherwise operations such as "mv x x"
         * will not work because the source and target nodes are the same. */
        if (!strcmp(name, inode->name) && !inode->deleted) {
            return inode;
        }
    }
    return 0;
}

struct lo_inode *create_node_locked(struct lo_inode *parent, const char *name)
{
    struct lo_inode *node;
    size_t namelen = strlen(name);

    node = calloc(1, sizeof(struct lo_inode));
    if (!node) {
        return NULL;
    }
    node->name = malloc(namelen + 1);
    if (!node->name) {
        free(node);
        return NULL;
    }
    memcpy(node->name, name, namelen + 1);
    node->namelen = namelen;
    //node->ino = fuse->global->inode_ctr++;
    //node->gen = fuse->global->next_generation++;

    /* store this for mapping (debugging) */
    node->lo_ino = (uintptr_t) node;
    node->deleted = 0;
#ifdef ENABLE_EXTFUSE
	node->pino = parent->ino == FUSE_ROOT_ID ? FUSE_ROOT_ID : (uintptr_t) parent;
#endif
    acquire_node_locked(node);
    add_node_to_parent_locked(node, parent);
    return node;
}

static int rename_node_locked(struct lo_inode *node, const char *name)
{
    size_t namelen = strlen(name);

    /* make the storage bigger without actually changing the name
     * in case an error occurs part way */
    if (namelen > node->namelen) {
        char* new_name = realloc(node->name, namelen + 1);
        if (!new_name) {
            return -ENOMEM;
        }
        node->name = new_name;
    }

    memcpy(node->name, name, namelen + 1);
    node->namelen = namelen;
    return 0;
}

#if 0
static struct lo_inode* acquire_or_create_child_locked(
        struct lo_inode* parent, const char* name)
{
    struct lo_inode* child = lookup_child_by_name_locked(parent, name);
    if (child) {
        acquire_node_locked(child);
    } else {
        child = create_node_locked(parent, name);
    }
    return child;
}
#endif

static char *construct_child_path(const char *ppath, const char *cname,
		char *buf, size_t bufsize)
{
    size_t pathlen = strlen(ppath);
    size_t namelen = strlen(cname);
    size_t childlen = pathlen + namelen + 1;
    char* actual;

    if (bufsize <= childlen) {
        return NULL;
    }

    memcpy(buf, ppath, pathlen);
    buf[pathlen] = '/';
    actual = buf + pathlen + 1;
    memcpy(actual, cname, namelen + 1);
	return actual;
}

/* Finds the absolute path of a file within a given directory.
 * Performs a case-insensitive search for the file and sets the buffer to the path
 * of the first matching file.  If 'search' is zero or if no match is found, sets
 * the buffer to the path that the file would have, assuming the name were case-sensitive.
 *
 * Populates 'buf' with the path and returns the actual name (within 'buf') on success,
 * or returns NULL if the path is too long for the provided buffer.
 */
static char* find_file_within(const char* path, const char* name,
        char* buf, size_t bufsize, int search)
{
    //size_t pathlen = strlen(path);
    //size_t namelen = strlen(name);
    //size_t childlen = pathlen + namelen + 1;
    char* actual = construct_child_path(path, name, buf, bufsize);
	if (!actual)
		return NULL;
    //if (bufsize <= childlen) {
    //    return NULL;
    //}

    //memcpy(buf, path, pathlen);
    //buf[pathlen] = '/';
    //actual = buf + pathlen + 1;
    //memcpy(actual, name, namelen + 1);

    if (search && access(buf, F_OK)) {
        struct dirent* entry;
        DIR* dir = opendir(path);
        if (!dir) {
            ERROR("[%s:%d] opendir %s failed: %s\n",
                    __func__, __LINE__, path, strerror(errno));
            return actual;
        }
        while ((entry = readdir(dir))) {
            if (!strcmp(entry->d_name, name)) {
                /* we have a match - replace the name, don't need to copy the null again */
                memcpy(actual, entry->d_name, strlen(name));
                break;
            }
        }
        closedir(dir);
    }
    return actual;
}

static void create_negative_entry(fuse_req_t req, fuse_ino_t pino,
                  const char *name, const char *cpath,
                  struct fuse_entry_param *e)
{
	memset(e, 0, sizeof(*e));

	/* negative entry */
	e->entry_timeout = lo_entry_valid_time(req);

	INFO("[%d] \t NEGATIVE LOOKUP(%s) @ 0x%"PRIx64"\n",
			gettid(), name, (uint64_t)pino);

#ifdef ENABLE_EXTFUSE_LOOKUP
	int res;
	struct lo_data *lo_data = get_lo_data(req);
	pthread_mutex_lock(&lo_data->mutex);
	/* negative entries have nlookup=0, ino=0 */
	res = lookup_insert(get_lo_data(req)->ebpf_ctxt, pino, name, 0, e);
	pthread_mutex_unlock(&lo_data->mutex);
	if (res)
		ERROR("[%d] \t LOOKUP negative node %s insertion failed: %s\n",
			gettid(), cpath, strerror(errno));
#endif
	fuse_reply_entry(req, e);
}

/*
 * @time parameter signifies that this request is generate explicitly,
 * and is not a case of performance optimization (e.g., readdir ahead)
 */
int create_entry(fuse_req_t req, struct lo_inode* pinode,
                  const char *name, const char *cpath,
                  struct fuse_entry_param *e, const char *op, int time)
{
	/* insert lo_inode into the hash table */
	struct lo_inode *inode;
	struct lo_data *lo_data = get_lo_data(req);
	int64_t res;

	/* Assign the stats of the newly created directory */
	memset(e, 0, sizeof(*e));

	/* Assign the stats of the newly created directory */
	res = lstat(cpath, &e->attr);
	if (time) {
		generate_end_time(req);
		populate_time(req);
	}

	if (res) {
		if (!strcmp(op, "lookup") && errno == ENOENT)
			create_negative_entry(req, (uintptr_t)pinode, name, cpath, e);
		else {
			ERROR("[%d] \t %s(%s) lstat(%s) failed: %s\n",
				gettid(), op, name, cpath, strerror(errno));
			fuse_reply_err(req, errno);
		}
		return -1;
	} else {
		pthread_mutex_lock(&lo_data->mutex);
		inode = lookup_child_by_name_locked(pinode, name);
    	if (inode)
			acquire_node_locked(inode);
    	else
			inode = create_node_locked(pinode, name);
		if (!inode) {
			ERROR("[%d] \t %s(%s) node creation failed: %s\n",
					gettid(), op, name, strerror(errno));
			pthread_mutex_unlock(&lo_data->mutex);
			if (time)
				fuse_reply_err(req, ENOMEM);
			return -1;
		}

		INFO("[%d] \t %s new node %s id: %p\n",
				gettid(), op, cpath, inode);

		/* optimization entries have nlookup=0 */
		if (!time)
			inode->nlookup = 0;

		inode->ino = e->attr.st_ino;
		inode->dev = e->attr.st_dev;

		e->attr_timeout = lo_attr_valid_time(req);
		e->entry_timeout = lo_entry_valid_time(req);

		/* store this for mapping (debugging) */
		e->ino = inode->lo_ino;

#ifdef ENABLE_EXTFUSE_LOOKUP
		res = lookup_fetch(get_lo_data(req)->ebpf_ctxt, inode->pino,
				inode->name);
		if (res && !errno) {
			INFO("[%d] \t Fetched %s nlookup: %ld inode->nlookup: %ld\n",
				gettid(), res < 0 ? "stale" : "", res, inode->nlookup);
			if (res < 0)
				res = -res;
			inode->nlookup = res + 1;
		}
		res = lookup_insert(get_lo_data(req)->ebpf_ctxt, inode->pino,
				inode->name, inode->nlookup, e);
		if (res)
			ERROR("[%d] \t %s new node %s id: %p: %s\n",
				gettid(), op, cpath, inode, strerror(errno));
#endif
		pthread_mutex_unlock(&lo_data->mutex);
		return 0;
	}
}

void stackfs_ll_link(fuse_req_t req, fuse_ino_t ino, fuse_ino_t newparent,
		      const char *newname)
{
	INCR_COUNTER(link);
	ERROR("[%s:%d]!!!!!!!!!!!!!!!!!!!!!!!\n", __func__, __LINE__);
	fuse_reply_err(req, EINVAL);
}

static void stackfs_ll_symlink(fuse_req_t req, const char *link,
				fuse_ino_t pino, const char *name)
{
	int res;
	struct fuse_entry_param e;

    struct lo_inode* pinode;
    char ppath[PATH_MAX];
    char cpath[PATH_MAX];

	struct lo_data *lo_data = get_lo_data(req);

	INCR_COUNTER(symlink);
	INFO("SYMLINK @ 0x%"PRIx64" name: %s link: %s\n", (uint64_t)pino, name, link);

	pthread_mutex_lock(&lo_data->mutex);
    pinode = lookup_node_and_path_by_id_locked(req, pino, ppath, PATH_MAX);
	pthread_mutex_unlock(&lo_data->mutex);

    INFO("[%d] SYMLINK (%s) on parent 0x%"PRIx64" (%s)\n",
					gettid(), name, (uint64_t)pino,
					pinode ? pinode->name : "?");
	if (!pinode ||
		!find_file_within(ppath, name, cpath, PATH_MAX, 1)) {
		ERROR("[%d] SYMLINK (%s) on parent 0x%"PRIx64" (%s) failed: %s\n",
				gettid(), name, (uint64_t)pino,
				ppath, strerror(ENOENT));
		fuse_reply_err(req, ENOENT);
		return;
	}

	generate_start_time(req);

	res = symlink(link/*contents*/, cpath/*newpath*/);
	if (res == -1) {
		generate_end_time(req);
		populate_time(req);

		/* Error occurred while creating link */
		ERROR("[%d] SYMLINK (%s, %s) failed: %s\n",
				gettid(), link, cpath, strerror(errno));
		fuse_reply_err(req, errno);
		return;
	}

	res = create_entry(req, pinode, name, cpath, &e, "symlink", 1);
	if (!res) {
		INFO("[%d] SYMLINK(%s, %s)\n", gettid(), name, cpath);
		fuse_reply_entry(req, &e);
	}
}

#if HAVE_ACCESS
static void stackfs_ll_access(fuse_req_t req, fuse_ino_t ino, int mask)
{
	ssize_t res;

	char path[PATH_MAX];

	struct lo_inode* inode;
	struct lo_data *lo_data = get_lo_data(req);

	INCR_COUNTER(access);
	pthread_mutex_lock(&lo_data->mutex);
    inode = lookup_node_and_path_by_id_locked(req, ino, path, PATH_MAX);
	pthread_mutex_unlock(&lo_data->mutex);

    INFO("[%d] ACCESS on 0x%"PRIx64" (%s) \n",
					gettid(), (uint64_t)ino, inode ? inode->name : "?");
	if (!inode) {
		ERROR("[%d] ACCESS 0x%"PRIx64" mask %d failed: %s\n",
			gettid(), (uint64_t)ino, mask, strerror(ENOENT));
		fuse_reply_err(req, ENOENT);
		return;
	}

	generate_start_time(req);
	res = access(path, mask);
	generate_end_time(req);
	populate_time(req);

    if (res == -1) {
        ERROR("access(%s, %d) failed: %s\n", path, mask, strerror(errno));
		fuse_reply_err(req, errno);
	} else
		fuse_reply_err(req, res);
}
#endif

static void stackfs_ll_readlink(fuse_req_t req, fuse_ino_t ino)
{
	char path[PATH_MAX];
	char linkname[PATH_MAX];

	struct lo_inode* inode;
	struct lo_data *lo_data = get_lo_data(req);

	ssize_t res;

	INCR_COUNTER(readlink);

	pthread_mutex_lock(&lo_data->mutex);
    inode = lookup_node_and_path_by_id_locked(req, ino, path, PATH_MAX);
	pthread_mutex_unlock(&lo_data->mutex);

    INFO("[%d] READLINK on 0x%"PRIx64" (%s) \n",
					gettid(), (uint64_t)ino, inode ? inode->name : "?");
	if (!inode) {
		ERROR("[%d] READLINK 0x%"PRIx64" failed: %s\n",
				gettid(), (uint64_t)ino, strerror(ENOENT));
		fuse_reply_err(req, ENOENT);
		return;
	}

	generate_start_time(req);
    res = readlink(path, linkname, PATH_MAX - 1);
	generate_end_time(req);
	populate_time(req);

    if (res == -1) {
        ERROR("readlink(%s) failed: %s\n", path, strerror(errno));
		fuse_reply_err(req, errno);
        return;
    }

	linkname[res] = '\0';
	INFO("readlink(%s) -> %s\n", path, linkname);
	fuse_reply_buf(req, linkname, res);
}

static void stackfs_ll_lookup(fuse_req_t req, fuse_ino_t pino,
						const char *name)
{
	int res;
	struct fuse_entry_param e;

	struct lo_inode* pinode;
	char ppath[PATH_MAX];
	char cpath[PATH_MAX];

	struct lo_data *lo_data = get_lo_data(req);

	INCR_COUNTER(lookup);

	pthread_mutex_lock(&lo_data->mutex);
    pinode = lookup_node_and_path_by_id_locked(req, pino, ppath, PATH_MAX);
	pthread_mutex_unlock(&lo_data->mutex);

    INFO("[%d] LOOKUP(%s) @ 0x%"PRIx64" (%s)\n",
				gettid(), name, (uint64_t)pino, pinode ? pinode->name : "?");

	if (!pinode || !find_file_within(ppath, name, cpath, PATH_MAX, 1)) {
		create_negative_entry(req, pino, name, cpath, &e);
		return;
	}

	generate_start_time(req);

	res = create_entry(req, pinode, name, cpath, &e, "lookup", 1);
	if (!res) {
		INFO("[%d] \t LOOKUP %s\n", gettid(), cpath);
		fuse_reply_entry(req, &e);
	}
}

static void stackfs_ll_getattr(fuse_req_t req, fuse_ino_t ino,
					struct fuse_file_info *fi)
{
	int res;
	struct stat stbuf;

	char path[PATH_MAX];
	struct lo_inode *inode;

	(void) fi;

	double attr_timeout;
	struct lo_data *lo_data = get_lo_data(req);

	INCR_COUNTER(getattr);

	pthread_mutex_lock(&lo_data->mutex);
    inode = lookup_node_and_path_by_id_locked(req, ino, path, PATH_MAX);
	pthread_mutex_unlock(&lo_data->mutex);

	if (!inode) {
		ERROR("getattr(0x%"PRIx64") failed: %s", (uint64_t)ino, strerror(ENOENT));
		fuse_reply_err(req, ENOENT);
		return;
	}

    INFO("[%d] GETATTR on 0x%"PRIx64" (%s)\n",
					gettid(), (uint64_t)ino, path);

	generate_start_time(req);
	res = lstat(path, &stbuf);
	generate_end_time(req);
	populate_time(req);

	if (res == -1) {
		ERROR("stat: getattr(%s) failed: %s\n", path, strerror(errno));
		fuse_reply_err(req, errno);
		return;
	}

	attr_timeout = lo_attr_valid_time(req);

#ifdef ENABLE_EXTFUSE_ATTR
	pthread_mutex_lock(&lo_data->mutex);
	attr_insert(lo_data->ebpf_ctxt, (uintptr_t)inode->lo_ino,
			&stbuf, attr_timeout);
	pthread_mutex_unlock(&lo_data->mutex);
#endif

	fuse_reply_attr(req, &stbuf, attr_timeout);
}

static void stackfs_ll_setattr(fuse_req_t req, fuse_ino_t ino,
		struct stat *attr, int to_set, struct fuse_file_info *fi)
{
	int res;
	struct stat stbuf;

	char path[PATH_MAX];
	struct lo_inode *inode;

	(void) fi;

	struct lo_data *lo_data = get_lo_data(req);
	double attr_timeout;

	INCR_COUNTER(setattr);

	pthread_mutex_lock(&lo_data->mutex);
    inode = lookup_node_and_path_by_id_locked(req, ino, path, PATH_MAX);
	pthread_mutex_unlock(&lo_data->mutex);

	if (!inode) {
		ERROR("setattr(0x%"PRIx64") failed: %s\n",
				(uint64_t)ino, strerror(ENOENT));
		fuse_reply_err(req, ENOENT);
		return;
	}

    INFO("[%d] SETATTR on 0x%"PRIx64" (%s)\n",
					gettid(), (uint64_t)ino, path);

	generate_start_time(req);

	/*Truncate*/
	if (to_set & FUSE_SET_ATTR_SIZE) {
		size_t size = attr->st_size; 

		INFO("[%d] \t TRUNCATE on 0x%"PRIx64" (%s) size: %ju\n",
						gettid(), (uint64_t)ino, path, size);

		res = truncate64(path, size);
		if (res != 0) {
			generate_end_time(req);
			populate_time(req);

			ERROR("[%d] \t truncate: setattr(%s) failed: %s\n",
				gettid(), path, strerror(errno));
			fuse_reply_err(req, errno);
			return;
		}
	}

	/* Update Time */
	if (to_set & (FUSE_SET_ATTR_ATIME | FUSE_SET_ATTR_MTIME)) {
		struct utimbuf tv;
		tv.actime = attr->st_atime;
		tv.modtime = attr->st_mtime;
		INFO("[%d] \t UTIME on 0x%"PRIx64" (%s)\n",
						gettid(), (uint64_t)ino, path);
		res = utime(path, &tv);
		if (res != 0) {
			generate_end_time(req);
			populate_time(req);

			ERROR("[%d] \t utime: setattr(%s) failed: %s\n",
				gettid(), path, strerror(errno));
			fuse_reply_err(req, errno);
			return;
		}
	}

	/*chown*/
	if (to_set & (FUSE_SET_ATTR_UID | FUSE_SET_ATTR_GID)) {
		uid_t uid = attr->st_uid;
		gid_t gid = attr->st_gid;

		INFO("[%d] \t CHOWN on 0x%"PRIx64" (%s) uid: %d gid: %d\n",
			gettid(), (uint64_t)ino, path, uid, gid);

		res = lchown(path, uid, gid);
		if (res != 0) {
			generate_end_time(req);
			populate_time(req);

			ERROR("[%d] \t lchown: setattr(%s) failed: %s\n",
				gettid(), path, strerror(errno));
			fuse_reply_err(req, errno);
			return;
		}
	}

	/*chmod*/
	if (to_set & FUSE_SET_ATTR_MODE) {
		mode_t mode = attr->st_mode;

		INFO("[%d] \t CHMOD on 0x%"PRIx64" (%s) mode: %d\n",
			gettid(), (uint64_t)ino, path, mode);
		
		res = chmod(path, mode);
		if (res != 0) {
			generate_end_time(req);
			populate_time(req);

			ERROR("[%d] \t chmod: setattr(%s) failed: %s\n",
				gettid(), path, strerror(errno));
			fuse_reply_err(req, errno);
			return;
		}
	}

	memset(&stbuf, 0, sizeof(stbuf));

	res = lstat(path, &stbuf);
	generate_end_time(req);
	populate_time(req);

	if (res != 0) {
		ERROR("[%d] \t lstat: setattr(%s) failed: %s\n",
				gettid(), path, strerror(errno));
		fuse_reply_err(req, errno);
		return;
	}

	attr_timeout = lo_attr_valid_time(req);

#ifdef ENABLE_EXTFUSE_ATTR
	pthread_mutex_lock(&lo_data->mutex);
	attr_insert(lo_data->ebpf_ctxt, (uintptr_t)inode->lo_ino,
			&stbuf, attr_timeout);
	pthread_mutex_unlock(&lo_data->mutex);
#endif

	fuse_reply_attr(req, &stbuf, attr_timeout);
}

static void stackfs_ll_create(fuse_req_t req, fuse_ino_t pino,
		const char *name, mode_t mode, struct fuse_file_info *fi)
{
	int fd, res;
	struct fuse_entry_param e;

    struct lo_inode* pinode;
    char ppath[PATH_MAX];
    char cpath[PATH_MAX];

	struct lo_data *lo_data = get_lo_data(req);

	INCR_COUNTER(create);

	pthread_mutex_lock(&lo_data->mutex);
    pinode = lookup_node_and_path_by_id_locked(req, pino, ppath, PATH_MAX);
	pthread_mutex_unlock(&lo_data->mutex);

	if (!pinode || !find_file_within(ppath, name, cpath, PATH_MAX, 1)) {
		ERROR("[%d] CREATE (%s, 0%o) failed: %s\n",
				gettid(), name, mode, strerror(ENOENT));
		fuse_reply_err(req, ENOENT);
		return;
	}

	INFO("[%d] CREATE (%s, 0%o) on parent 0x%"PRIx64" (%s)\n",
				gettid(), name, mode, (uint64_t)pino, ppath);

	generate_start_time(req);
	fd = open(cpath, fi->flags, mode);
	if (fd == -1) {
		generate_end_time(req);
		populate_time(req);

		ERROR("[%d] \t create(%s) failed: %s\n",
				gettid(), cpath, strerror(errno));
		fuse_reply_err(req, errno);
		return;
	}

	res = create_entry(req, pinode, name, cpath, &e, "create", 1);
	if (res) {
		close(fd);
	} else {
		fi->fh = fd;
		INFO("[%d] \t CREATE %s fd: 0x%"PRIx64"\n", gettid(), cpath, fi->fh);
		fuse_reply_create(req, &e, fi);
	}
}

static void stackfs_ll_mknod(fuse_req_t req, fuse_ino_t pino,
                const char *name, mode_t mode, dev_t rdev)
{
	int res;
	struct fuse_entry_param e;

    struct lo_inode* pinode;
    char ppath[PATH_MAX];
    char cpath[PATH_MAX];

	struct lo_data *lo_data = get_lo_data(req);

	INCR_COUNTER(mknod);

	pthread_mutex_lock(&lo_data->mutex);
    pinode = lookup_node_and_path_by_id_locked(req, pino, ppath, PATH_MAX);
	pthread_mutex_unlock(&lo_data->mutex);

	if (!pinode ||
		!find_file_within(ppath, name, cpath, PATH_MAX, 1)) {
		ERROR("[%d] MKNOD (%s, 0%o) failed: %s\n",
				gettid(), name, mode, strerror(ENOENT));
		fuse_reply_err(req, ENOENT);
		return;
	}

    INFO("[%d] MKNOD (%s, 0%o) on parent 0x%"PRIx64" (%s)\n",
				gettid(), name, mode, (uint64_t)pino, ppath);

	generate_start_time(req);
	res = mknod(cpath, mode, rdev);
	if (res == -1) {
		generate_end_time(req);
		populate_time(req);

		/* Error occurred while creating the directory */
		ERROR("[%d] \t mknod(%s) failed: %s\n",
				gettid(), cpath, strerror(errno));
		fuse_reply_err(req, errno);
		return;
	}

	res = create_entry(req, pinode, name, cpath, &e, "mknod", 1);
	if (!res) {
		INFO("[%d] \t MKNOD %s\n", gettid(), cpath);
		fuse_reply_entry(req, &e);
	}
}

static void stackfs_ll_mkdir(fuse_req_t req, fuse_ino_t pino,
				const char *name, mode_t mode)
{
	int res;
	struct fuse_entry_param e;

    struct lo_inode* pinode;
    char ppath[PATH_MAX];
    char cpath[PATH_MAX];

	struct lo_data *lo_data = get_lo_data(req);

	INCR_COUNTER(mkdir);

	pthread_mutex_lock(&lo_data->mutex);
    pinode = lookup_node_and_path_by_id_locked(req, pino, ppath, PATH_MAX);
	pthread_mutex_unlock(&lo_data->mutex);

	if (!pinode ||
		!find_file_within(ppath, name, cpath, PATH_MAX, 1)) {
		ERROR("[%d] MKDIR (%s, 0%o) failed: %s\n",
				gettid(), name, mode, strerror(ENOENT));
		fuse_reply_err(req, ENOENT);
		return;
	}

    INFO("[%d] MKDIR (%s, 0%o) on parent 0x%"PRIx64" (%s)\n",
				gettid(), name, mode, (uint64_t)pino, ppath);

	generate_start_time(req);
	res = mkdir(cpath, mode);
	if (res == -1) {
		generate_end_time(req);
		populate_time(req);

		/* Error occurred while creating the directory */
		ERROR("[%d] \t mkdir(%s) failed: %s\n",
				gettid(), cpath, strerror(errno));
		fuse_reply_err(req, errno);
		return;
	}

	res = create_entry(req, pinode, name, cpath, &e, "mkdir", 1);
	if (!res) {
		INFO("[%d] \t MKDIR %s\n", gettid(), cpath);
		fuse_reply_entry(req, &e);
	}
}

static void stackfs_ll_open(fuse_req_t req, fuse_ino_t ino,
					struct fuse_file_info *fi)
{
	int fd;

    struct lo_inode* inode;
    char path[PATH_MAX];

	struct lo_data *lo_data = get_lo_data(req);
	int flags = fi->flags;

	INCR_COUNTER(open);

	pthread_mutex_lock(&lo_data->mutex);
    inode = lookup_node_and_path_by_id_locked(req, ino, path, PATH_MAX);
	pthread_mutex_unlock(&lo_data->mutex);

	if (!inode) {
		ERROR("[%d] OPEN @ 0x%"PRIx64" flags: %d failed: %s\n",
				gettid(), (uint64_t)ino, flags, strerror(ENOENT));
		fuse_reply_err(req, ENOENT);
		return;
	}

    INFO("[%d] OPEN @ 0x%"PRIx64" (%s) flags: %d\n",
		gettid(), (uint64_t)ino, path, flags);

	generate_start_time(req);
	fd = open(path, flags);
	generate_end_time(req);
	populate_time(req);

	if (fd == -1) {
		ERROR("[%d] \t OPEN @ 0x%"PRIx64" (%s) flags: %d failed: %s\n",
				gettid(), (uint64_t)ino, path, flags, strerror(errno));
		fuse_reply_err(req, errno);
		return;
	}

	fi->fh = fd;
	//fi->lower_fd = fd;

	INFO("[%d] \t OPEN @ 0x%"PRIx64" path: %s fd: 0x%"PRIx64"\n",
		gettid(), (uint64_t)ino, path, fi->fh);

	fuse_reply_open(req, fi);
}

static void stackfs_ll_opendir(fuse_req_t req, fuse_ino_t ino,
					struct fuse_file_info *fi)
{
	DIR *dp;
	struct lo_dirptr *d;
    struct lo_inode* inode;
    char path[PATH_MAX];

	struct lo_data *lo_data = get_lo_data(req);

	INCR_COUNTER(opendir);

	pthread_mutex_lock(&lo_data->mutex);
    inode = lookup_node_and_path_by_id_locked(req, ino, path, PATH_MAX);
	pthread_mutex_unlock(&lo_data->mutex);

	if (!inode) {
		ERROR("[%d] OPEN @ 0x%"PRIx64" failed: %s\n",
				gettid(), (uint64_t)ino, strerror(ENOENT));
		fuse_reply_err(req, ENOENT);
		return;
	}

    INFO("[%d] OPENDIR @ 0x%"PRIx64" (%s)\n",
		gettid(), (uint64_t)ino, path);

	generate_start_time(req);
	dp = opendir(path);
	generate_end_time(req);
	populate_time(req);

	if (dp == NULL) {
		ERROR("[%d] \t OPENDIR @ 0x%"PRIx64" (%s) failed: %s\n",
				gettid(), (uint64_t)ino, path, strerror(errno));
		fuse_reply_err(req, errno);
		return;
	}

	d = malloc(sizeof(struct lo_dirptr));
	d->dp = dp;
	d->offset = 0;
	d->entry = NULL;

	INFO("[%d] \t OPENDIR @ 0x%"PRIx64" d %p dp %p path: %s fd: 0x%x\n",
			gettid(), (uint64_t)ino, d, dp, path, dirfd(dp));

	fi->fh = (uintptr_t) d;
	//fi->lower_fd = dirfd(dp);
	fuse_reply_open(req, fi);
}

#ifdef ENABLE_EXTFUSE_ATTR
static void cache_attr(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *fi)
{
	struct stat stbuf;
	memset(&stbuf, 0, sizeof(stbuf));
	int res = fstat(fi->fh, &stbuf);
	if (res) {
		ERROR("[%d] \t fstat: read(0x%"PRIx64") failed: %s\n",
			gettid(), fi->fh, strerror(errno));
	} else {
		struct lo_data *lo_data = get_lo_data(req);
		double attr_timeout = lo_attr_valid_time(req);
		struct lo_inode* inode;
		pthread_mutex_lock(&lo_data->mutex);
		inode = lookup_node_by_id_locked(req, ino);
		attr_insert(lo_data->ebpf_ctxt, (uintptr_t)inode->lo_ino,
				&stbuf, attr_timeout);
		pthread_mutex_unlock(&lo_data->mutex);
	}
}
#endif

static void stackfs_ll_read(fuse_req_t req, fuse_ino_t ino, size_t size,
				off_t offset, struct fuse_file_info *fi)
{
	(void) ino;

#ifdef DEBUG
    struct lo_inode* inode;
    char path[PATH_MAX];

	struct lo_data *lo_data = get_lo_data(req);

	pthread_mutex_lock(&lo_data->mutex);
    inode = lookup_node_and_path_by_id_locked(req, ino, path, PATH_MAX);
	pthread_mutex_unlock(&lo_data->mutex);

    INFO("[%d] READ @ 0x%"PRIx64" name: %s fd: 0x%"PRIx64" off : %lu, size : %zu\n",
				gettid(), (uint64_t)ino, inode ? path : "?", fi->fh, offset, size);
#endif

	INCR_COUNTER(read);

	if (USE_SPLICE) {
		struct fuse_bufvec buf = FUSE_BUFVEC_INIT(size);

		INFO("[%d] \t Splice Read: %s, fd: %ld off : %lu, size : %zu\n",
			gettid(), inode ? path : "?", fi->fh, offset, size);

		generate_start_time(req);
		buf.buf[0].flags = FUSE_BUF_IS_FD | FUSE_BUF_FD_SEEK;
		buf.buf[0].fd = fi->fh;
		buf.buf[0].pos = offset;
		generate_end_time(req);
		populate_time(req);
#ifdef ENABLE_EXTFUSE_ATTR
		cache_attr(req, ino, fi);
#endif
		fuse_reply_data(req, &buf, FUSE_BUF_SPLICE_MOVE);
	} else {
		int res;
		char *buf = (char *)malloc(size);
		if (!buf) {
			ERROR("[%d] \t Read @ 0x%"PRIx64" fd: 0x%"PRIx64" "
					"off : %lu, size : %zu failed: %s\n",
					gettid(), (uint64_t)ino, fi->fh, offset, size, strerror(ENOMEM));
			fuse_reply_err(req, ENOMEM);
			return;
		}

		INFO("[%d] \t Read @ 0x%"PRIx64" fd: 0x%"PRIx64" off : %lu, size : %zu\n",
					gettid(), (uint64_t)ino, fi->fh, offset, size);

		generate_start_time(req);
		res = pread(fi->fh, buf, size, offset);
		generate_end_time(req);
		populate_time(req);
#ifdef ENABLE_EXTFUSE_ATTR
		cache_attr(req, ino, fi);
#endif
		if (res == -1) {
			ERROR("[%d] \t Read @ 0x%"PRIx64" fd: 0x%"PRIx64" off : %lu, size : %zu failed: %s\n",
					gettid(), (uint64_t)ino, fi->fh, offset, size, strerror(errno));
			fuse_reply_err(req, errno);
		} else
			res = fuse_reply_buf(req, buf, res);
		free(buf);
	}
}

static void stackfs_ll_readdir(fuse_req_t req, fuse_ino_t ino, size_t size,
					off_t off, struct fuse_file_info *fi)
{
	(void) ino;
#if defined(DEBUG) || defined(ENABLE_READDIR_CACHING)
    struct lo_inode* inode;
    char path[PATH_MAX];

	struct lo_data *lo_data = get_lo_data(req);

	pthread_mutex_lock(&lo_data->mutex);
    inode = lookup_node_and_path_by_id_locked(req, ino, path, PATH_MAX);
	pthread_mutex_unlock(&lo_data->mutex);
#endif

#ifdef DEBUG
    INFO("[%d] READDIR @ 0x%"PRIx64" name: %s\n",
				gettid(), (uint64_t)ino, inode ? path : "?");
#endif

	struct lo_dirptr *d = lo_dirptr(fi);
	char *buf = malloc(size*sizeof(char));
	char *p = NULL;
	size_t rem;
	int err;
	char *name;

	INCR_COUNTER(readdir);

	if (!buf) {
		fuse_reply_err(req, ENOMEM);
		return;
	}

	generate_start_time(req);
	/* If offset is not same, need to seek it */
	if (off != d->offset) {
		seekdir(d->dp, off);
		d->entry = NULL;
		d->offset = off;
	}
	p = buf;
	rem = size;
	while (1) {
		size_t entsize;
		off_t nextoff;

		if (!d->entry) {
			errno = 0;
			d->entry = readdir(d->dp);
			if (!d->entry) {
				if (errno && rem == size) {
					err = errno;
					goto error;
				}
				break;
			}
		}
		nextoff = telldir(d->dp);

		struct stat st = {
			.st_ino = d->entry->d_ino,
			.st_mode = d->entry->d_type << 12,
		};
		name = d->entry->d_name;
		entsize = fuse_add_direntry(req, p, rem, name, &st, nextoff);
	/* The above function returns the size of the entry size even though
	* the copy failed due to smaller buf size, so I'm checking after this
	* function and breaking out incase we exceed the size.
	*/
		if (entsize > rem)
			break;

#ifdef ENABLE_READDIR_CACHING
		if (strcmp(name, ".") && strcmp(name, "..")) {
			char cpath[PATH_MAX];
			if (inode && construct_child_path(path, name, cpath, PATH_MAX)) {
				struct fuse_entry_param e;
				int res = create_entry(req, inode, name, cpath, &e, "readdir", 0);
				if (res)
					ERROR("\t Failed to create direntry for (%s, %s)\n",
							path, name);
			}
		}
#endif

		p += entsize;
		rem -= entsize;

		d->entry = NULL;
		d->offset = nextoff;
	}

	generate_end_time(req);
	populate_time(req);
	fuse_reply_buf(req, buf, size - rem);
	free(buf);

	return;

error:
	generate_end_time(req);
	populate_time(req);
	free(buf);

	fuse_reply_err(req, err);
}

static void stackfs_ll_release(fuse_req_t req, fuse_ino_t ino,
					struct fuse_file_info *fi)
{
	(void) ino;

	INFO("[%d] RELEASE @ 0x%"PRIx64"\n", gettid(), (uint64_t)ino);

#ifdef DEBUG
    struct lo_inode* inode;
    char path[PATH_MAX];

	struct lo_data *lo_data = get_lo_data(req);

	pthread_mutex_lock(&lo_data->mutex);
    inode = lookup_node_and_path_by_id_locked(req, ino, path, PATH_MAX);
	pthread_mutex_unlock(&lo_data->mutex);

	(void)inode;
    INFO("[%d] \t RELEASE @ 0x%"PRIx64" (%s) fd: 0x%"PRIx64"\n",
					gettid(), (uint64_t)ino, inode ? path : "?", fi->fh);
#endif

	INCR_COUNTER(release);

	generate_start_time(req);
	close(fi->fh);
	generate_end_time(req);
	populate_time(req);

	fuse_reply_err(req, 0);
}

static void stackfs_ll_releasedir(fuse_req_t req, fuse_ino_t ino,
						struct fuse_file_info *fi)
{
	struct lo_dirptr *d = lo_dirptr(fi);

	(void) ino;
#ifdef DEBUG
    struct lo_inode* inode;
    char path[PATH_MAX];

	struct lo_data *lo_data = get_lo_data(req);

	pthread_mutex_lock(&lo_data->mutex);
    inode = lookup_node_and_path_by_id_locked(req, ino, path, PATH_MAX);
	pthread_mutex_unlock(&lo_data->mutex);

    INFO("[%d] RELEASEDIR @ 0x%"PRIx64" name: %s\n",
				gettid(), (uint64_t)ino, inode ? path : "?");
#endif

	INCR_COUNTER(releasedir);

	generate_start_time(req);
	closedir(d->dp);
	generate_end_time(req);
	populate_time(req);
	free(d);
	fuse_reply_err(req, 0);
}

static void stackfs_ll_write(fuse_req_t req, fuse_ino_t ino, const char *buf,
			size_t size, off_t off, struct fuse_file_info *fi)
{
	int res;
	(void) ino;

#ifdef DEBUG
    struct lo_inode* inode;
    char path[PATH_MAX];

	struct lo_data *lo_data = get_lo_data(req);

	pthread_mutex_lock(&lo_data->mutex);
    inode = lookup_node_and_path_by_id_locked(req, ino, path, PATH_MAX);
	pthread_mutex_unlock(&lo_data->mutex);

    INFO("[%d] WRITE @ 0x%"PRIx64" (%s) fd: 0x%"PRIx64" off : %lu, size : %zu\n",
				gettid(), (uint64_t)ino, inode ? path : "?", fi->fh, off, size);
#endif

	INCR_COUNTER(write);

	generate_start_time(req);
	res = pwrite(fi->fh, buf, size, off);
	generate_end_time(req);
	populate_time(req);

	if (res == -1) {
		ERROR("[%d] \t Write @ 0x%"PRIx64" fd: 0x%"PRIx64" off : %lu, size : %zu "
				"failed: %s\n", gettid(), (uint64_t)ino, fi->fh, off, size,
				strerror(errno));
		fuse_reply_err(req, errno);
	} else
		fuse_reply_write(req, res);
}

#if USE_SPLICE
static void stackfs_ll_write_buf(fuse_req_t req, fuse_ino_t ino,
		struct fuse_bufvec *buf, off_t off, struct fuse_file_info *fi)
{
	int res;
	(void) ino;

	struct fuse_bufvec dst = FUSE_BUFVEC_INIT(fuse_buf_size(buf));

#ifdef DEBUG
    struct lo_inode* inode;
    char path[PATH_MAX];

	struct lo_data *lo_data = get_lo_data(req);

	pthread_mutex_lock(&lo_data->mutex);
    inode = lookup_node_and_path_by_id_locked(req, ino, path, PATH_MAX);
	pthread_mutex_unlock(&lo_data->mutex);

    INFO("[%d] WRITE @ 0x%"PRIx64" (%s) fd: 0x%"PRIx64" off : %lu, "
		"size : %ju\n", gettid(), (uint64_t)ino, inode ? path : "?",
		fi->fh, off, buf->buf[0].size);
#endif

	INCR_COUNTER(write);

	generate_start_time(req);
	dst.buf[0].flags = FUSE_BUF_IS_FD | FUSE_BUF_FD_SEEK;
	dst.buf[0].fd = fi->fh;
	dst.buf[0].pos = off;
	res = fuse_buf_copy(&dst, buf, FUSE_BUF_SPLICE_NONBLOCK);
	generate_end_time(req);
	populate_time(req);
	if (res >= 0)
		fuse_reply_write(req, res);
	else
		fuse_reply_err(req, res);
}
#endif

static void delete_node(struct lo_inode *pinode, const char *name,
				struct lo_data *lo_data, const char *op)
{
    struct lo_inode* cinode;

	/* remove node */
	pthread_mutex_lock(&lo_data->mutex);
    cinode = lookup_child_by_name_locked(pinode, name);
    if (cinode) {
#ifdef ENABLE_EXTFUSE_LOOKUP
	/*
	 * XXX doing this here frees up hashtable, which otherwise happens
	 * lazily during forget
	 */
	int64_t res = lookup_fetch(lo_data->ebpf_ctxt, cinode->pino, cinode->name);
	if (res > 0) {
		ERROR("[%d] \t %s: Found non-stale node %s (0x%"PRIx64") parent 0x%lx nlookup %ld\n",
			gettid(), op, cinode->name, (uintptr_t)cinode, cinode->pino, res);
		errno = EINVAL;
	} else if (res < 0 && !errno) {
		cinode->nlookup = -res;
		INFO("[%d] \t %s: Found stale node %s (0x%"PRIx64") parent 0x%lx nlookup %ld\n",
			gettid(), op, cinode->name, (uintptr_t)cinode, cinode->pino, res);
	} else if (errno == ENOENT) {
		INFO("[%d] \t %s: Nothing found for node %s (0x%"PRIx64") parent 0x%lx\n",
			gettid(), op, cinode->name, (uintptr_t)cinode, cinode->pino);
		res = 0; // do not care if nothing exists
	} else {
		ERROR("Failed to fetch node %s parent 0x%lx from hashtab error: %s\n",
			cinode->name, cinode->pino, strerror(errno));
	}
	if (res) {
		res = lookup_delete(lo_data->ebpf_ctxt, cinode->pino, cinode->name,
					cinode->lo_ino);
		if (res && errno != ENOENT) {
			ERROR("Failed to delete node %s parent 0x%lx from hashtab\n",
				cinode->name, cinode->pino);
		}
	}
#endif
        cinode->deleted = 1;
    }
	pthread_mutex_unlock(&lo_data->mutex);
}

static void stackfs_ll_unlink(fuse_req_t req, fuse_ino_t pino,
						const char *name)
{
	int64_t res;

    struct lo_inode* pinode;

    char ppath[PATH_MAX];
    char cpath[PATH_MAX];

	struct lo_data *lo_data = get_lo_data(req);

	INCR_COUNTER(unlink);

	pthread_mutex_lock(&lo_data->mutex);
    pinode = lookup_node_and_path_by_id_locked(req, pino, ppath, PATH_MAX);
	pthread_mutex_unlock(&lo_data->mutex);

	if (!pinode || !find_file_within(ppath, name, cpath, PATH_MAX, 1)) {
		ERROR("[%d] UNLINK %s parent 0x%"PRIx64" failed: %s",
				gettid(), name, (uint64_t)pino, strerror(ENOENT));
		fuse_reply_err(req, ENOENT);
		return;
	}

    INFO("[%d] UNLINK %s parent 0x%"PRIx64" (%s)\n",
					gettid(), name, (uint64_t)pino, ppath);

	generate_start_time(req);
	res = unlink(cpath);
	generate_end_time(req);
	populate_time(req);

	if (res == -1) {
		ERROR("[%d] \t UNLINK %s parent 0x%"PRIx64" failed: %s",
				gettid(), cpath, (uint64_t)pino, strerror(errno));
		fuse_reply_err(req, errno);
		return;
	} 

	delete_node(pinode, name, lo_data, "UNLINK");
	fuse_reply_err(req, res);
}

static void stackfs_ll_rmdir(fuse_req_t req, fuse_ino_t pino,
						const char *name)
{
	int64_t res;

    struct lo_inode* pinode;

    char ppath[PATH_MAX];
    char cpath[PATH_MAX];

	struct lo_data *lo_data = get_lo_data(req);

	INCR_COUNTER(rmdir);

	pthread_mutex_lock(&lo_data->mutex);
    pinode = lookup_node_and_path_by_id_locked(req, pino, ppath, PATH_MAX);
	pthread_mutex_unlock(&lo_data->mutex);

	if (!pinode || !find_file_within(ppath, name, cpath, PATH_MAX, 1)) {
		ERROR("[%d] RMDIR %s parent 0x%"PRIx64" failed: %s",
				gettid(), cpath, (uint64_t)pino, strerror(errno));
		fuse_reply_err(req, ENOENT);
		return;
	}

    INFO("[%d] RMDIR %s parent 0x%"PRIx64" (%s)\n",
		gettid(), name, (uint64_t)pino, ppath);

	generate_start_time(req);
	res = rmdir(cpath);
	generate_end_time(req);
	populate_time(req);

	if (res == -1) {
		ERROR("[%d] \t rmdir(%s) failed: %s\n",
			gettid(), name, strerror(errno));
		fuse_reply_err(req, errno);
		return;
	} 

	delete_node(pinode, name, lo_data, "RMDIR");
	fuse_reply_err(req, res);
}

static void forget_inode(fuse_req_t req, fuse_ino_t ino, uint64_t nlookup)
{
	struct lo_data *lo_data = get_lo_data(req);
	struct lo_inode *inode;
	int64_t res;

#ifdef ENABLE_EXTFUSE
	// fast path inodes
	if ((int64_t)ino < 0) {
		INFO("[%d] \t FORGET: negative inode %"PRIu64"\n",
			gettid(), (uint64_t) ino);
		return;
	}
#endif

	pthread_mutex_lock(&lo_data->mutex);

	inode = lookup_node_by_id_locked(req, ino);

	INFO("[%d] \t FORGET %"PRIu64"(%ld) @ 0x%"PRIx64" (%s)\n",
		gettid(), nlookup, nlookup, (uint64_t)ino,
		inode ? inode->name : "?");

	if (!inode) {
		ERROR("[%d] \t FORGET #%"PRIu64"(%ld) @ 0x%"PRIx64" (%s)\n",
				gettid(), nlookup, nlookup, (uint64_t)ino,
				inode ? inode->name : "INVALID!");
		pthread_mutex_unlock(&lo_data->mutex);
		return;
	}

#ifdef ENABLE_EXTFUSE_LOOKUP
	INFO("[%d] \t FORGET ino %p (nlookup: %ld inode->nlookup: %ld)\n",
			gettid(), inode, nlookup, inode->nlookup);

	res = lookup_fetch(get_lo_data(req)->ebpf_ctxt, inode->pino, inode->name);
	if (res && !errno) {
		INFO("[%d] \t Fetched %s nlookup: %ld inode->nlookup: %ld\n",
			gettid(), res < 0 ? "stale" : "", res, inode->nlookup);
		if (res < 0)
			res = -res;
	} else if (errno == ENOENT)
		res = 0; // do not care if nothing exists
	else {
		ERROR("[%d] \t Failed to fetch node %s parent 0x%lx from hashtab\n",
			gettid(), inode->name, inode->pino);
		pthread_mutex_unlock(&lo_data->mutex);
		return;
	}
	if (res && res < nlookup) {
		ERROR("[%d] \t Invalid nlookup value (expected: %ld found %ld)\n",
			gettid(), res, nlookup);
	}
	if (res > 0)
		inode->nlookup = res;
#endif

	assert(inode->nlookup >= nlookup);
	while (nlookup--)
		release_node_locked(req, inode);

	pthread_mutex_unlock(&lo_data->mutex);

	(void) res;
}

static void stackfs_ll_forget(fuse_req_t req, fuse_ino_t ino, uint64_t nlookup)
{
	INCR_COUNTER(forget);
	INFO("[%d] FORGET nlookup: %zu\n", gettid(), nlookup);
	generate_start_time(req);
	forget_inode(req, ino, nlookup);
	generate_end_time(req);
	populate_time(req);

	fuse_reply_none(req);
}

static void stackfs_ll_forget_multi(fuse_req_t req, size_t count,
					struct fuse_forget_data *forgets)
{
	size_t i;
	INCR_COUNTER(forget_multi);
	INFO("[%d] BATCH_FORGET count : %zu\n", gettid(), count);
	generate_start_time(req);
	for (i = 0; i < count; i++) {
		forget_inode(req, forgets[i].ino, forgets[i].nlookup);
	}
	generate_end_time(req);
	populate_time(req);
	fuse_reply_none(req);
}

#ifdef HAVE_FLUSH
static void stackfs_ll_flush(fuse_req_t req, fuse_ino_t ino,
					struct fuse_file_info *fi)
{
#ifdef DEBUG
    struct lo_inode* inode;
    char path[PATH_MAX] = {0};

	struct lo_data *lo_data = get_lo_data(req);

	pthread_mutex_lock(&lo_data->mutex);
    inode = lookup_node_and_path_by_id_locked(req, ino, path, PATH_MAX);
	pthread_mutex_unlock(&lo_data->mutex);

	INFO("[%d] FLUSH @ 0x%"PRIx64" (%s) fd: 0x%"PRIx64"\n",
					gettid(), (uint64_t)ino, inode ? path : "?", fi->fh);
#endif

	INCR_COUNTER(flush);

	generate_start_time(req);
	generate_end_time(req);
	populate_time(req);
	fuse_reply_err(req, 0);
}
#endif

static void stackfs_ll_rename(fuse_req_t req, fuse_ino_t oldpino,
			    const char *old_name, fuse_ino_t newpino,
			    const char *new_name, unsigned int flags)
{
    struct lo_inode* old_pinode;
    struct lo_inode* new_pinode;
    struct lo_inode* cinode;
    char old_ppath[PATH_MAX];
    char new_ppath[PATH_MAX];
    char old_cpath[PATH_MAX];
    char new_cpath[PATH_MAX];

	int64_t res;
	struct lo_data *lo_data = get_lo_data(req);

	INCR_COUNTER(rename);

	pthread_mutex_lock(&lo_data->mutex);
    old_pinode = lookup_node_and_path_by_id_locked(req, oldpino,
            old_ppath, PATH_MAX);
    new_pinode = lookup_node_and_path_by_id_locked(req, newpino,
            new_ppath, PATH_MAX);

	INFO("[%d] RENAME %s->%s @ 0x%"PRIx64" (%s) -> 0x%"PRIx64" (%s)\n",
				gettid(), old_name, new_name,
            	(uint64_t)oldpino, old_pinode ? old_pinode->name : "?",
            	(uint64_t)newpino, new_pinode ? new_pinode->name : "?");

    if (!old_pinode || !new_pinode) {
    	ERROR("1: rename %s @ 0x%"PRIx64" -> %s 0x%"PRIx64" failed: %s\n",
            	old_name, (uint64_t)oldpino, new_name,
				(uint64_t)newpino, strerror(ENOENT));
		fuse_reply_err(req, ENOENT);
        goto lookup_error;
    }

    cinode = lookup_child_by_name_locked(old_pinode, old_name);
    if (!cinode || get_node_path_locked(cinode,
            old_cpath, PATH_MAX) < 0) {
    	ERROR("2: rename %s @ 0x%"PRIx64" (%s), %s 0x%"PRIx64" (%s) failed: %s\n",
            	old_name, (uint64_t)oldpino, old_ppath,
				new_name, (uint64_t)newpino, new_ppath,
				strerror(ENOENT));
		fuse_reply_err(req, ENOENT);
        goto lookup_error;
    }

    acquire_node_locked(cinode);
	pthread_mutex_unlock(&lo_data->mutex);

    int search = old_pinode != new_pinode;
	if (!find_file_within(new_ppath, new_name, new_cpath,
							PATH_MAX, search)) {
    	ERROR("3: rename %s @ 0x%"PRIx64" (%s), %s 0x%"PRIx64" (%s) failed: %s\n",
            	old_name, (uint64_t)oldpino, old_ppath,
				new_name, (uint64_t)newpino, new_ppath,
				strerror(ENOENT));
		fuse_reply_err(req, ENOENT);
        goto io_error;
    }

	INFO("[%d] \t rename(%s, %s) old nlookup: %ld\n",
		gettid(), old_cpath, new_cpath, cinode->nlookup);

#ifdef ENABLE_EXTFUSE_LOOKUP
	res = lookup_fetch(lo_data->ebpf_ctxt, cinode->pino, cinode->name);
	if (res > 0 && !errno) {
		ERROR("[%d] \t Rename: Found non-stale node %s parent 0x%lx nlookup %ld\n",
			gettid(), cinode->name, cinode->pino, res);
		errno = EINVAL;
		fuse_reply_err(req, errno);
		goto io_error;
	} else if (res < 0 && !errno) {
		cinode->nlookup = -res;
	} else if (errno == ENOENT)
		res = 0; // do not care if nothing exists
	else {
		ERROR("Failed to fetch node %s parent 0x%lx from hashtab error: %s\n",
			cinode->name, cinode->pino, strerror(errno));
		fuse_reply_err(req, errno);
		goto io_error;
	}
	if (res)
		lookup_delete(lo_data->ebpf_ctxt, cinode->pino,
			cinode->name, cinode->lo_ino);
#endif

	generate_start_time(req);
	res = rename(old_cpath, new_cpath);
	generate_end_time(req);
	populate_time(req);

	if (res == -1) {
    	ERROR("rename(%s, %s) failed: %s\n",
            	old_cpath, new_cpath, strerror(errno));
		fuse_reply_err(req, errno);
		goto io_error;
	}

	pthread_mutex_lock(&lo_data->mutex);
    res = rename_node_locked(cinode, new_name);
	if (res) {
    	ERROR("[%d] \t rename_node_locked(%s, %s) failed: %s\n",
            	gettid(), old_cpath, new_cpath, strerror(-res));
		fuse_reply_err(req, -res);
		goto done;
	}

    if (oldpino != newpino) {
        remove_node_from_parent_locked(req, cinode);
		add_node_to_parent_locked(cinode, new_pinode);
    }

	fuse_reply_err(req, 0);
    goto done;

io_error:
	pthread_mutex_lock(&lo_data->mutex);
done:
    release_node_locked(req, cinode);
lookup_error:
	pthread_mutex_unlock(&lo_data->mutex);
}

static void stackfs_ll_statfs(fuse_req_t req, fuse_ino_t ino)
{
	int res;
	struct statvfs buf = {0};
    char path[PATH_MAX];
	struct lo_data *lo_data = get_lo_data(req);

	INCR_COUNTER(statfs);

	pthread_mutex_lock(&lo_data->mutex);
    res = get_node_path_locked(&lo_data->root, path, PATH_MAX);
	pthread_mutex_unlock(&lo_data->mutex);

    if (res < 0) {
    	INFO("[%d] STATFS @ 0x%"PRIx64" failed %s\n",
						gettid(), (uint64_t)ino, strerror(ENOENT));
		fuse_reply_err(req, ENOENT);
		return;
    }

    INFO("[%d] STATFS @ 0x%"PRIx64" (%s)\n", gettid(), (uint64_t)ino, path);

	res = -EINVAL;
	if (ino) {
		generate_start_time(req);
		res = statvfs(path, &buf);
		generate_end_time(req);
		populate_time(req);
	}

	if (!res)
		fuse_reply_statfs(req, &buf);
	else {
		INFO("[%d] \t STATFS @ 0x%"PRIx64" (%s) failed %s\n",
						gettid(), (uint64_t)ino, path, strerror(errno));
		fuse_reply_err(req, res);
	}
}

static void stackfs_ll_fsyncdir(fuse_req_t req, fuse_ino_t ino, int datasync,
			      struct fuse_file_info *fi)
{
	int res;

	struct lo_dirptr *d = (struct lo_dirptr *) (uintptr_t) fi->fh;
	DIR *dp = d->dp;
	int fd = dirfd(dp);

	INCR_COUNTER(fsyncdir);

	INFO("[%d] FSYNCDIR %"PRIu64" fd: 0x%x datasync: %d\n",
			gettid(), (uint64_t)ino, fd, datasync);

	generate_start_time(req);
	if (datasync)
		res = fdatasync(fd);
	else
		res = fsync(fd);
	generate_end_time(req);
	populate_time(req);

	if (res == -1) {
		ERROR("[%d] \t FSYNCDIR %"PRIu64" fd: 0x%x datasync: %d failed: %s\n",
			gettid(), (uint64_t)ino, fd, datasync, strerror(errno));
		fuse_reply_err(req, errno);
	} else
		fuse_reply_err(req, res);
}

static void stackfs_ll_fsync(fuse_req_t req, fuse_ino_t ino, int datasync,
			struct fuse_file_info *fi)
{
	int res;
	int fd = fi->fh;

	INCR_COUNTER(fsync);

	INFO("[%d] FSYNC %"PRIu64" fd: 0x%x datasync: %d\n",
			gettid(), (uint64_t)ino, fd, datasync);

	generate_start_time(req);
	if (datasync)
		res = fdatasync(fd);
	else
		res = fsync(fd);
	generate_end_time(req);
	populate_time(req);

	if (res == -1) {
		ERROR("[%d] \t FSYNC %"PRIu64" fd: 0x%"PRIx64" datasync: %d failed: %s\n",
			gettid(), (uint64_t)ino, fi->fh, datasync, strerror(errno));
		fuse_reply_err(req, errno);
	} else
		fuse_reply_err(req, res);
}

#if  HAVE_XATTR
static void stackfs_ll_listxattr(fuse_req_t req, fuse_ino_t ino, size_t size)
{
	ssize_t res;
	char path[PATH_MAX];

	struct lo_inode* inode;
	struct lo_data *lo_data = get_lo_data(req);

	INCR_COUNTER(listxattr);

	pthread_mutex_lock(&lo_data->mutex);
    inode = lookup_node_and_path_by_id_locked(req, ino, path, PATH_MAX);
	pthread_mutex_unlock(&lo_data->mutex);

    INFO("[%d] LISTXATTR @ 0x%"PRIx64" (%s) size %ju\n",
					gettid(), (uint64_t)ino, inode ? inode->name : "?", size);
	if (!inode) {
		ERROR("[%d] \t LISTXATTR 0x%"PRIx64" size %ju failed: %s",
			gettid(), (uint64_t)ino, size, strerror(ENOENT));
		fuse_reply_err(req, ENOENT);
		return;
	}

	INFO("[%d] \t LISTXATTR %"PRIu64" (%s) size: %ju\n",
			gettid(), (uint64_t)ino, path, size);

	if (size) {
		char *list = (char *) malloc(size);
		if (!list) {
			ERROR("[%d] \t listxattr @ %"PRIu64" (%s) size: %ju failed: %s\n",
					gettid(), (uint64_t)ino, path, size, strerror(ENOMEM));
			fuse_reply_err(req, ENOMEM);
			return;
		}

		generate_start_time(req);
		res = llistxattr(path, list, size);
		generate_end_time(req);
		populate_time(req);
		if (res > 0)
			fuse_reply_buf(req, list, res);
		else {
			if (errno != ENODATA)
				ERROR("[%d] \t listxattr @ %"PRIu64" (%s) size: %ju failed: %s\n",
						gettid(), (uint64_t)ino, path, size, strerror(errno));
			fuse_reply_err(req, errno);
		}

		free(list);
	} else {
		generate_start_time(req);
		res = llistxattr(path, NULL, 0);
		generate_end_time(req);
		populate_time(req);
		if (res >= 0)
			fuse_reply_xattr(req, res);
		else {
			if (errno != ENODATA)
				ERROR("[%d] \t listxattr @ %"PRIu64" (%s) size: %ju failed: %s\n",
						gettid(), (uint64_t)ino, path, size, strerror(errno));
			fuse_reply_err(req, errno);
		}
	}
}

static void stackfs_ll_removexattr(fuse_req_t req, fuse_ino_t ino, const char *name)
{
	int res;
	char path[PATH_MAX];

	struct lo_inode* inode;
	struct lo_data *lo_data = get_lo_data(req);

	INCR_COUNTER(removexattr);

	pthread_mutex_lock(&lo_data->mutex);
    inode = lookup_node_and_path_by_id_locked(req, ino, path, PATH_MAX);
	pthread_mutex_unlock(&lo_data->mutex);

    INFO("[%d] REMOVEXATTR @ 0x%"PRIx64" (%s) key %s\n",
					gettid(), (uint64_t)ino, inode ? inode->name : "?", name);
	if (!inode) {
		ERROR("[%d] \t REMOVEXATTR 0x%"PRIx64" key %s failed: %s",
			gettid(), (uint64_t)ino, name, strerror(ENOENT));
		fuse_reply_err(req, ENOENT);
		return;
	}

	INFO("[%d] \t REMOVEXATTR %"PRIu64" (%s) key: %s\n",
			gettid(), (uint64_t)ino, path, name);

	generate_start_time(req);
	res = lremovexattr(path, name);
	generate_end_time(req);
	populate_time(req);
	if (res == -1) {
		if (errno != ENODATA)
			ERROR("[%d] \t removexattr @ %"PRIu64" (%s) key: %s failed: %s\n",
					gettid(), (uint64_t)ino, path, name, strerror(errno));
		fuse_reply_err(req, errno);
	} else
		fuse_reply_err(req, res);
}

static void stackfs_ll_setxattr(fuse_req_t req, fuse_ino_t ino,
				const char *name, const char *value,
				size_t size, int flags)
{
	int res;
	char path[PATH_MAX];

	struct lo_inode* inode;
	struct lo_data *lo_data = get_lo_data(req);

	INCR_COUNTER(setxattr);

	pthread_mutex_lock(&lo_data->mutex);
    inode = lookup_node_and_path_by_id_locked(req, ino, path, PATH_MAX);
	pthread_mutex_unlock(&lo_data->mutex);

    INFO("[%d] SETXATTR @ 0x%"PRIx64" (%s) key %s value %s size %ju "
			"flags %d\n", gettid(), (uint64_t)ino, inode ? inode->name : "?",
			name, value, size, flags);
	if (!inode) {
		ERROR("[%d] \t SETXATTR 0x%"PRIx64" key %s value %s size %ju flags %d "
				"failed: %s", gettid(), (uint64_t)ino, name, value, size, flags,
				strerror(ENOENT));
		fuse_reply_err(req, ENOENT);
		return;
	}

	INFO("[%d] \t SETXATTR %"PRIu64" (%s) key: %s value: %s size: %ju, "
			"flags: %d\n", gettid(), (uint64_t)ino, path, name, value,
			size, flags);

	generate_start_time(req);
	res = lsetxattr(path, name, value, size, flags);
	generate_end_time(req);
	populate_time(req);
	if (res == -1) {
		if (errno != ENODATA)
			ERROR("[%d] \t SETXATTR @ %"PRIu64" (%s) key: %s value: %s "
					"size: %ju failed: %s\n", gettid(), (uint64_t)ino, path,
					name, value, size, strerror(errno));
		fuse_reply_err(req, errno);
	} else
		fuse_reply_err(req, res);
}

static void stackfs_ll_getxattr(fuse_req_t req, fuse_ino_t ino,
					const char *name, size_t size)
{
	ssize_t res;
	char path[PATH_MAX];

	struct lo_inode* inode;
	struct lo_data *lo_data = get_lo_data(req);

	INCR_COUNTER(getxattr);

	pthread_mutex_lock(&lo_data->mutex);
    inode = lookup_node_and_path_by_id_locked(req, ino, path, PATH_MAX);
	pthread_mutex_unlock(&lo_data->mutex);

    INFO("[%d] GETXATTR @ 0x%"PRIx64" (%s) key %s size %ju\n",
			gettid(), (uint64_t)ino, inode ? inode->name : "?", name, size);
	if (!inode) {
		ERROR("[%d] GETXATTR 0x%"PRIx64" key %s size %ju failed: %s",
			gettid(), (uint64_t)ino, name, size, strerror(ENOENT));
		fuse_reply_err(req, ENOENT);
		return;
	}

	INFO("[%d] \t GETXATTR %"PRIu64" (%s) key: %s size: %ju\n",
					gettid(), (uint64_t)ino, path, name, size);

	if (size) {
		char *value = (char *) malloc(size);
		if (!value) {
			ERROR("[%d] \t getxattr @ %"PRIu64" (%s) key: %s size: %ju "
					"failed: %s\n", gettid(), (uint64_t)ino, path, name,
					size, strerror(ENOMEM));
			fuse_reply_err(req, ENOMEM);
			return;
		}

		generate_start_time(req);
		res = lgetxattr(path, name, value, size);
		generate_end_time(req);
		populate_time(req);
		if (res > 0)
			fuse_reply_buf(req, value, res);
		else {
			if (errno != ENODATA)
				ERROR("[%d] \t getxattr @ %"PRIu64" (%s) key: %s size: %ju "
					"failed: %s\n", gettid(), (uint64_t)ino, path, name,
					size, strerror(errno));
			fuse_reply_err(req, errno);
		}

		free(value);
	} else {
		generate_start_time(req);
		res = lgetxattr(path, name, NULL, 0);
		generate_end_time(req);
		populate_time(req);
		if (res >= 0)
			fuse_reply_xattr(req, res);
		else {
			if (errno != ENODATA)
				ERROR("[%d] \t getxattr @ %"PRIu64" (%s) key: %s size: %ju "
						"failed: %s\n", gettid(), (uint64_t)ino, path, name,
						size, strerror(errno));
			fuse_reply_err(req, errno);
		}
	}
}
#endif

#ifdef ENABLE_EXTFUSE
static void stackfs_ll_destroy(void *userdata)
{
	struct lo_data *lo = (struct lo_data*) userdata;
	if (lo->ebpf_ctxt) {
		ERROR( "Unloading ExtFUSE prog\n");
		ebpf_fini(lo->ebpf_ctxt);
	}
}

static void stackfs_ll_init(void *userdata,
		    struct fuse_conn_info *conn)
{
	struct lo_data *lo = (struct lo_data*) userdata;

	if (conn->capable & FUSE_CAP_EXTFUSE) {
		/* FIXME hard-coded bpf file path */
		INFO("ALERT: Attempting to load ExtFUSE eBPF bytecode from /tmp/extfuse.o\n");
		lo->ebpf_ctxt = ebpf_init("/tmp/extfuse.o");
		if (!lo->ebpf_ctxt) {
			ERROR("\tENABLE_EXTFUSE failed %s\n",
				strerror(errno));
		} else {
			ERROR("\tExtFUSE eBPF bytecode loaded: ctxt=0x%lx fd=%d\n",
				(unsigned long)lo->ebpf_ctxt, lo->ebpf_ctxt->ctrl_fd);
			conn->want |= FUSE_CAP_EXTFUSE;
			conn->extfuse_prog_fd = lo->ebpf_ctxt->ctrl_fd;
		}
	} else {
			ERROR("\tExtFUSE not enabled flags:0x%lx ebpf_flag:0x%lx mask:0x%lx\n",
				(unsigned long)conn->capable, (unsigned long)FUSE_CAP_EXTFUSE,
				(unsigned long)(conn->capable & FUSE_CAP_EXTFUSE));
	}
}
#endif

static void stackfs_ll_fallocate(fuse_req_t req, fuse_ino_t ino, int mode,
		off_t offset, off_t length, struct fuse_file_info *fi)
{
	int res;

#ifdef DEBUG
    struct lo_inode* inode;
    char path[PATH_MAX];

	struct lo_data *lo_data = get_lo_data(req);

	pthread_mutex_lock(&lo_data->mutex);
    inode = lookup_node_and_path_by_id_locked(req, ino, path, PATH_MAX);
	pthread_mutex_unlock(&lo_data->mutex);

	INFO("[%d] FALLOCATE @ 0x%"PRIx64" (%s) fd: 0x%"PRIx64" "
					"mode %x, offset: %llu, length: %llu\n", gettid(),
					(uint64_t)ino, inode? path : "?", fi->fh, mode,
					(unsigned long long) offset, (unsigned long long)length);
#endif

	INCR_COUNTER(fallocate);

	generate_start_time(req);
	res = fallocate(fi->fh, mode, offset, length);
	generate_end_time(req);
	populate_time(req);

	if (res) {
		ERROR("[%d] fallocate @ 0x%"PRIx64" fd: 0x%"PRIx64" mode %x, "
				"offset: %llu, length: %llu failed: %s", gettid(),
				(uint64_t)ino, fi->fh, mode, (unsigned long long) offset,
				(unsigned long long)length, strerror(errno));
		fuse_reply_err(req, errno);
	} else
		fuse_reply_err(req, res);
}

#ifdef HAVE_BMAP
static void stackfs_ll_bmap(fuse_req_t req, fuse_ino_t ino, size_t blocksize,
			  uint64_t idx)
{
	fuse_reply_err(req, EINVAL);
}
#endif

#ifdef HAVE_POLL
static void stackfs_ll_poll(fuse_req_t req, fuse_ino_t ino,
			  struct fuse_file_info *fi, struct fuse_pollhandle *ph)
{
	fuse_reply_err(req, EINVAL);
}
#endif

#ifdef HAVE_UTIMENSAT
static int stackfs_ll_utimes(const char *vpath, const struct timespec tv[2])
{
	fuse_reply_err(req, EINVAL);
}
#endif

static struct fuse_lowlevel_ops hello_ll_oper = {
#ifdef ENABLE_EXTFUSE
	.init			= 	stackfs_ll_init,
	.destroy		= 	stackfs_ll_destroy,
#endif
	.lookup			=	stackfs_ll_lookup,
	.getattr		=	stackfs_ll_getattr,
#ifdef HAVE_ACCESS
	.access			=	stackfs_ll_access,
#endif
	.readlink		=	stackfs_ll_readlink,
	.rename			=	stackfs_ll_rename,
	.symlink		=	stackfs_ll_symlink,
	.link			=	stackfs_ll_link,
	.statfs			=	stackfs_ll_statfs,
	.setattr		=	stackfs_ll_setattr,
#ifdef HAVE_FLUSH
	.flush			=	stackfs_ll_flush,
#endif
	.fsyncdir		=	stackfs_ll_fsyncdir,
	.fsync			=	stackfs_ll_fsync,
	.forget			=	stackfs_ll_forget,
	.forget_multi	=	stackfs_ll_forget_multi,
	.create			=	stackfs_ll_create,
	.open			=	stackfs_ll_open,
	.read			=	stackfs_ll_read,
	.write			=	stackfs_ll_write,
#if	USE_SPLICE
	.write_buf		=	stackfs_ll_write_buf,
#endif
	.release		=	stackfs_ll_release,
	.unlink			=	stackfs_ll_unlink,
	.mkdir			=	stackfs_ll_mkdir,
	.mknod			=	stackfs_ll_mknod,
	.rmdir			=	stackfs_ll_rmdir,
	.opendir		=	stackfs_ll_opendir,
	.readdir		=	stackfs_ll_readdir,
	.releasedir		=	stackfs_ll_releasedir,
#if	HAVE_XATTR
	.getxattr		=	stackfs_ll_getxattr,
	.setxattr		= 	stackfs_ll_setxattr,
	.listxattr		= 	stackfs_ll_listxattr,
	.removexattr	=	stackfs_ll_removexattr,
#endif
#ifdef HAVE_LOCK
	.getlk			=	stackfs_ll_getlk,
	.setlk			=	stackfs_ll_setlk,
	.flock			=	stackfs_ll_flock,
#endif
#ifdef HAVE_BMAP
	.bmap			=	stackfs_ll_bmap,
#endif
#ifdef HAVE_IOCTL
	.ioctl			=	stackfs_ll_ioctl,
#endif
#ifdef HAVE_POLL
	.poll			=	stackfs_ll_poll,
#endif
	.fallocate		=	stackfs_ll_fallocate,
#ifdef HAVE_UTIMENSAT
	.utimens		=	stackfs_ll_utimes,
#endif
};

static const struct fuse_opt stackfs_opts[] = {
	STACKFS_OPT("-r %s", root),
	STACKFS_OPT("--rootdir=%s", root),
	STACKFS_OPT("--statsdir=%s", statsDir),
	STACKFS_OPT("--attrval=%lf", attr_valid),
	FUSE_OPT_KEY("--tracing", 1),
	FUSE_OPT_KEY("-h", 0),
	FUSE_OPT_KEY("--help", 0),
	FUSE_OPT_END
};

static int stackfs_process_arg(void *data, const char *arg,
				int key, struct fuse_args *outargs)
{
	struct stackFS_info *s_info = data;

	(void)outargs;
	(void)arg;

	switch (key) {
	case 0:
		s_info->is_help = 1;
		return 0;
	case 1:
		s_info->tracing	= 1;
		return 0;
	default:
		return 1;
	}
}

#ifdef ENABLE_STATS
static void print_stats(void)
{
	printf("lookup:	     %ld\n", stats.lookup);
	printf("getattr:     %ld\n", stats.getattr);
	printf("access:      %ld\n", stats.access);
	printf("readlink:    %ld\n", stats.readlink);
	printf("rename:      %ld\n", stats.rename);
	printf("symlink:     %ld\n", stats.symlink);
	printf("link:        %ld\n", stats.link);
	printf("statfs:      %ld\n", stats.statfs);
	printf("setattr:     %ld\n", stats.setattr);
	printf("flush:       %ld\n", stats.flush);
	printf("fsyncdir:    %ld\n", stats.fsyncdir);
	printf("fsync:       %ld\n", stats.fsync);
	printf("forget:      %ld\n", stats.forget);
	printf("btchforget:  %ld\n", stats.forget_multi);
	printf("create:      %ld\n", stats.create);
	printf("open:        %ld\n", stats.open);
	printf("read:        %ld\n", stats.read);
	printf("write:       %ld\n", stats.write);
	printf("release:     %ld\n", stats.release);
	printf("unlink:      %ld\n", stats.unlink);
	printf("mkdir:       %ld\n", stats.mkdir);
	printf("mknod:       %ld\n", stats.mknod);
	printf("rmdir:       %ld\n", stats.rmdir);
	printf("opendir:     %ld\n", stats.opendir);
	printf("readdir:     %ld\n", stats.readdir);
	printf("releasedir:  %ld\n", stats.releasedir);
#if HAVE_XATTR
    printf("getxattr:	 %ld\n", stats.getxattr);
    printf("setxattr:    %ld\n", stats.setxattr);
    printf("listxattr:   %ld\n", stats.listxattr);
    printf("removexattr: %ld\n", stats.removexattr);
#endif
    printf("getlk:       %ld\n", stats.getlk);
    printf("setlk:       %ld\n", stats.setlk);
    printf("flock:       %ld\n", stats.flock);
    printf("bmap:        %ld\n", stats.bmap);
    printf("ioctl:       %ld\n", stats.ioctl);
    printf("poll:        %ld\n", stats.poll);
    printf("fallocate:   %ld\n", stats.fallocate);
#ifdef HAVE_UTIMENSAT
	printf("utimes:      %ld\n", stats.utimes);
#endif
}

//void handle_sigusr1(int sig) {
void handle_sigusr1(int sig, siginfo_t *sinfo, void* cont) {
	printf("Caught USR1 signal\n");
	print_stats();
	//(*old.sa_handler)(sig);
	(*old.sa_sigaction)(sig, sinfo, cont);
}

void set_signhandlers(void)
{
	int status;
    struct sigaction sa;

    // Setup the sighub handler
    //sa.sa_handler = &handle_sigusr1;
	sa.sa_sigaction = &handle_sigusr1;

    // Restart the system call, if at all possible
    //sa.sa_flags = SA_RESTART;
	sa.sa_flags = SA_SIGINFO;

    // Block every signal during the handler
    sigfillset(&sa.sa_mask);

    // Intercept SIGHUP and SIGINT
	status = sigaction(SIGUSR1, &sa, &old);
    if (status == -1) {
		ERROR("Error: cannot handle SIGUSR1: %s", strerror(errno));
    } else {
		INFO("Signal handler for SIGUSR1 set to dump stats\n");
	}
}
#endif

int main(int argc, char **argv)
{
	int res = 0, err = 0;
	char *root = NULL;
	char *statsDir = NULL;
	char *resolved_statsDir = NULL;
	char *resolved_rootdir_path = NULL;
	int multithreaded;

	struct fuse_args args = FUSE_ARGS_INIT(argc, argv);
	/*Default entry/attr valid time is 1 sec*/
	struct stackFS_info s_info = {NULL, NULL, 1.0, 1.0, 0, 0};

#ifdef CACHE_ENTRY_ATTR
	s_info.attr_valid = BIG_TIMEOUT;
	s_info.entry_valid = BIG_TIMEOUT;
#endif

	res = fuse_opt_parse(&args, &s_info, stackfs_opts, stackfs_process_arg);

	if (res) {
		INFO("Failed to parse arguments\n");
		return -1;
	}

	if (s_info.is_help) {
		print_usage();
		return 0;
	}

	if (!s_info.root) {
		INFO("Root Directory is mandatory\n");
		print_usage();
		return -1;
	}

	if (s_info.statsDir) {
		statsDir = s_info.statsDir;
		resolved_statsDir = realpath(statsDir, NULL);
		if (resolved_statsDir == NULL) {
			INFO("There is a problem in resolving the stats ");
			INFO("Directory passed %s\n", statsDir);
			perror("Error");
			res = -1;
			goto out1;
		}
	}

	root = s_info.root;
	struct lo_data *lo = NULL;

	if (root) {
		lo = (struct lo_data *) calloc(1, sizeof(struct lo_data));
		if (!lo) {
			ERROR( "fuse: memory allocation failed\n");
			res = -1;
			goto out2; /* free the resolved_statsDir */
		}
		resolved_rootdir_path = realpath(root, NULL);
		if (!resolved_rootdir_path) {
			INFO("There is a problem in resolving the root ");
			INFO("Directory Passed %s\n", root);
			perror("Error");
			res = -1;
			goto out3; /* free both resolved_statsDir, lo */
		}
		if (res == 0) {
#ifdef ENABLE_EXTFUSE
			rootfd = open(root, O_PATH);
			if (rootfd == -1) {
				ERROR( "Failed to open rootdir %s: %s\n",
					root, strerror(errno));
				goto out4;
			} else {
				INFO("root %s\n", root);
			}
#endif
			(lo->root).name = resolved_rootdir_path;
			(lo->root).namelen = strlen(resolved_rootdir_path);
			(lo->root).ino = FUSE_ROOT_ID;
			(lo->root).nlookup = 2;
			lo->attr_valid = s_info.attr_valid;
			lo->entry_valid = s_info.entry_valid;
			/* Initialise the spin lock for table */
			pthread_mutex_init(&(lo->mutex), 0);
		}
	} else {
		res = -1;
		goto out2;
	}

	struct fuse_chan *ch;
	char *mountpoint;

	/* allow other users/apps to access the storage space */
    fuse_opt_add_arg(&args, "-oallow_other");

	res = fuse_parse_cmdline(&args, &mountpoint, &multithreaded, NULL);

	/* Initialise the spinlock before the logfile creation */
	pthread_mutex_init(&mutex, 0);

	ERROR("Multi Threaded : %d\n", multithreaded);

	if (res != -1) {
		ch = fuse_mount(mountpoint, &args);
		if (ch) {
			struct fuse_session *se;

			INFO("Mounted Successfully\n");
			se = fuse_lowlevel_new(&args, &hello_ll_oper,
						sizeof(hello_ll_oper), lo);
			if (se) {
				if (fuse_set_signal_handlers(se) != -1) {
#ifdef ENABLE_STATS
					stats_fd = open(USER_STATS_FILE, O_WRONLY | O_CREAT);
					if (stats_fd < 0)
						ERROR("Failed to create stats file\n");
					else {
						ERROR("Created stats file: %s\n", USER_STATS_FILE);
						set_signhandlers();
					}
#endif
					fuse_session_add_chan(se, ch);
					if (resolved_statsDir)
						fuse_session_add_statsDir(se,
							resolved_statsDir);

					if (multithreaded)
						err = fuse_session_loop_mt(se);
					else
						err = fuse_session_loop(se);
					(void) err;

					fuse_remove_signal_handlers(se);
					fuse_session_remove_statsDir(se);
					fuse_session_remove_chan(ch);
					INFO("fuse_remove_signal_handlers\n");
#ifdef ENABLE_STATS
					if (stats_fd > 0) {
						print_stats();
						close(stats_fd);
					}
#endif
				}
				fuse_session_destroy(se);
				INFO("fuse_session_destroy\n");
			}
			INFO("Function Trace : Unmount");
			fuse_unmount(mountpoint, ch);
		}
	}

	/* free the arguments */
	fuse_opt_free_args(&args);

	/* destroy the lock protecting the linked list of nodes */
	pthread_mutex_destroy(&(lo->mutex));

	/* destroy the lock protecting the log file */
	pthread_mutex_destroy(&mutex);

#ifdef ENABLE_EXTFUSE
	close(rootfd);
out4:
#endif

	if (resolved_rootdir_path)
		free(resolved_rootdir_path);
out3:
	if (lo)
		free(lo);
out2:
	if (resolved_statsDir)
		free(resolved_statsDir);
out1:
	return res;
}
