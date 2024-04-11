#include <linux/bpf.h>
#include <linux/version.h>

#ifndef __section
#define __section(NAME) __attribute__((section(NAME), used))
#endif

#define PIN_GLOBAL_NS 2

struct bpf_elf_map {
  __u32 type;
  __u32 size_key;
  __u32 size_value;
  __u32 max_elem;
  __u32 flags;
  __u32 id;
  __u32 pinning;
};

struct bpf_elf_map __section("maps") ddos_programs = {
    .type = BPF_MAP_TYPE_PROG_ARRAY,
    .size_key = sizeof(__u32),
    .size_value = sizeof(__u32),
    .max_elem = 63,
    .pinning = PIN_GLOBAL_NS,
};

static __u64 (*bpf_tail_call)(void *ctx, struct bpf_elf_map *prog_array_map,
                              __u32 index) = (void *)BPF_FUNC_tail_call;

#ifndef DDOS_ROOT_INDEX
// update this after adding a new plugin
#define DDOS_ROOT_INDEX 1
#endif

__section("xdp") int xdp_ddos(struct xdp_md *ctx) {
  bpf_tail_call(ctx, &ddos_programs, DDOS_ROOT_INDEX);
  return XDP_PASS;
}

char ____license[] __section("license") = "GPL";
int _version __section("version") = 1;
