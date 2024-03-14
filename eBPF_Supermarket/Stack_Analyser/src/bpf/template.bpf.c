
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#include "sa_ebpf.h"
#include "bpf/TemplateClass.h"
#include "task.h"

DeclareCommonMaps(__u32);
DeclareCommonVar();

const char LICENSE[] SEC("license") = "GPL";