/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
#ifndef __MEM_H
#define __MEM_H

#define CACHE_NAME_SIZE 32

struct slabrate_info {
	char name[CACHE_NAME_SIZE];
	__u64 count;
	__u64 size;
};

#endif /* __MEM_H */