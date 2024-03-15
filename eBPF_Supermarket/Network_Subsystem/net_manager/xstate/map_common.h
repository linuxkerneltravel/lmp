#ifndef __MAP_COMMON_H
#define __MAP_COMMON_H

#include "../common/common_params.h"
#include "../common/common_user_bpf_xdp.h"
#include "common_kern_user.h"

extern int open_map(const char *ifname, const char *map_name);
extern int bpf_map_update_elem_check(int map_fd, const void *key, const void *value, __u64 flags);

#endif