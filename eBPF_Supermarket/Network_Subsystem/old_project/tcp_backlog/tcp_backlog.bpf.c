// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2021 Sartura */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

/* begin kprobe/tcp_v4_conn_request*/
SEC("kprobe/tcp_v4_conn_request")
int BPF_KPROBE(tcp_v4_conn_request, struct sock *sk)
{ 
    // https://elixir.bootlin.com/linux/v5.15/source/include/net/sock.h#L948
    u32 sk_ack_backlog = BPF_CORE_READ(sk,sk_ack_backlog); //sk->sk_ack_backlog
    u32 sk_max_ack_backlog = BPF_CORE_READ(sk,sk_max_ack_backlog); //sk->sk_max_ack_backlog
    
    bpf_printk("%d,%d,%d",sk_ack_backlog,sk_max_ack_backlog,sk_ack_backlog>sk_max_ack_backlog);
}
/* end kprobe/tcp_v4_conn_request*/