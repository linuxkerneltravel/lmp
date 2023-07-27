#ifndef STACK_ANALYZER
#define STACK_ANALYZER

#define MAX_STACKS 32
#define MAX_ENTRIES 102400
#define COMM_LEN 16

#include <asm/types.h>

#define BPF_STACK_TRACE(name)                           \
    struct                                              \
    {                                                   \
        __uint(type, BPF_MAP_TYPE_STACK_TRACE);         \
        __uint(key_size, sizeof(__u32));                \
        __uint(value_size, MAX_STACKS * sizeof(__u64)); \
        __uint(max_entries, MAX_ENTRIES);               \
    } name SEC(".maps")

#define BPF_HASH(name, type1, type2)       \
    struct                                 \
    {                                      \
        __uint(type, BPF_MAP_TYPE_HASH);   \
        __uint(key_size, sizeof(type1));   \
        __uint(value_size, sizeof(type2)); \
        __uint(max_entries, MAX_ENTRIES);  \
    } name SEC(".maps")

#define BPF(type, name) (struct type##_bpf *)name
#define bpf_open_load(type, name) struct type##_bpf *name = type##_bpf__open_and_load()
#define bpf_destroy(type, name) type##_bpf__destroy(BPF(type, name))
#define bpf_attach(type, name) type##_bpf__attach(BPF(type, name))

#define KERNEL_STACK bpf_get_stackid(ctx, &stack_trace, BPF_F_FAST_STACK_CMP)
#define USER_STACK bpf_get_stackid(ctx, &stack_trace, BPF_F_FAST_STACK_CMP | BPF_F_USER_STACK)

typedef struct
{
    __u32 pid;
    __s32 ksid, usid;
} psid;

typedef struct
{
    char str[COMM_LEN];
} comm;

typedef enum 
{
	MOD_ON_CPU,
	MOD_OFF_CPU,
	MOD_MEM,
} MOD;

#endif