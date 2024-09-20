// Copyright 2023 The LMP Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// https://github.com/linuxkerneltravel/lmp/blob/develop/LICENSE
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// author: blown.away@qq.com
//
// netwatcher libbpf 内核<->用户 传递信息相关结构体

#ifndef __REDIS_HELPER_BPF_H
#define __REDIS_HELPER_BPF_H

#include "netwatcher.h"
#include "vmlinux.h"
#include <asm-generic/errno.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <string.h>

#define LRU_BITS 24
typedef struct redisObject {
    unsigned type:4;
    unsigned encoding:4;
    unsigned lru:24; 
    int refcount;
    void *ptr;
} robj;

struct client {
    u64 id;            /* Client incremental unique ID. */
    u64 conn;
    int resp;               /* RESP protocol version. Can be 2 or 3. */
    u64 db;            /* Pointer to currently SELECTed DB. */
    robj *name;             /* As set by CLIENT SETNAME. */
    char* querybuf;           /* Buffer we use to accumulate client queries. */
    unsigned long qb_pos;          /* The position we have read in querybuf. */
    char* pending_querybuf;
    unsigned long querybuf_peak;   /* Recent (100ms or more) peak of querybuf size. */
    int argc;               /* Num of arguments of current command. */
    robj **argv;            /* Arguments of current command. */
    unsigned long argv_len_sum;           /* Size of argv array (may be more than argc) */
};

#endif
