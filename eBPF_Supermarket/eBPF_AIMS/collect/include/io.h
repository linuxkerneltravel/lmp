#ifndef IO_H
#define IO_H

#include <asm/types.h>
#include "cpu.h"

struct io_stat {
	__u64 read_bytes;
	__u64 write_bytes;
	__u64 read_calls;
	__u64 write_calls;
	char comm[TASK_COMM_LEN];
};

#endif // IO_H 