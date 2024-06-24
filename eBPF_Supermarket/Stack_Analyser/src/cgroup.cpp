#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/vfs.h>
#include <linux/magic.h>
#include <fcntl.h>
#include "cgroup.h"

uint64_t get_cgroupid(const char *pathname)
{
    struct statfs fs;
    int err;
    struct cgid_file_handle *h;
    int mount_id;
    uint64_t ret;

    err = statfs(pathname, &fs);
    if (err != 0)
    {
        fprintf(stderr, "statfs on %s failed: %s\n", pathname, strerror(errno));
        exit(1);
    }

    if ((fs.f_type != (typeof(fs.f_type))CGROUP2_SUPER_MAGIC))
    {
        fprintf(stderr, "File %s is not on a cgroup2 mount.\n", pathname);
        exit(1);
    }

    h = (cgid_file_handle *)malloc(sizeof(struct cgid_file_handle));
    if (!h)
    {
        fprintf(stderr, "Cannot allocate memory.\n");
        exit(1);
    }

    h->handle_bytes = 8;
    err = name_to_handle_at(AT_FDCWD, pathname, (struct file_handle *)h, &mount_id, 0);
    if (err != 0)
    {
        fprintf(stderr, "name_to_handle_at failed: %s\n", strerror(errno));
        exit(1);
    }

    if (h->handle_bytes != 8)
    {
        fprintf(stderr, "Unexpected handle size: %d. \n", h->handle_bytes);
        exit(1);
    }

    ret = h->cgid;
    free(h);

    return ret;
}