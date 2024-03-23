#include <errno.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h> /* libbpf_num_possible_cpus */

#include "map_common.h"

#ifndef PATH_MAX
#define PATH_MAX	4096
#endif

int bpf_map_update_elem_check(int map_fd, const void *key, const void *value, __u64 flags){
    int err;

    err = bpf_map_update_elem(map_fd, key, value, flags);
    if (err < 0) {
		fprintf(stderr,
			"WARN: Failed to update bpf map file: err(%d):%s\n",
			errno, strerror(errno));
		return err;
	}
    printf("\nUpdated to map %d\n",map_fd);

    return 1;
}

int open_map(const char *ifname, const char *map_name){
    int len;
    char pin_dir[PATH_MAX];
    const char *pin_basedir =  "/sys/fs/bpf";
    struct bpf_map_info info = { 0 };

    /* Use the --dev name as subdir for finding pinned maps */
	len = snprintf(pin_dir, PATH_MAX, "%s/%s", pin_basedir, ifname);
	if (len < 0) {
		fprintf(stderr, "ERR: creating pin dirname\n");
		return -1;
	}

	
    int fd = open_bpf_map_file(pin_dir, map_name, &info);
	if (fd < 0) {
		return -1;
	}
    if (verbose) {
		printf("\nOpened BPF map\n");
		printf(" - BPF map (bpf_map_type:%d) fd: %d id:%d name:%s"
		       " key_size:%d value_size:%d max_entries:%d\n",
		       info.type, fd ,info.id, info.name,
		       info.key_size, info.value_size, info.max_entries
		       );
	}

    return fd;
}