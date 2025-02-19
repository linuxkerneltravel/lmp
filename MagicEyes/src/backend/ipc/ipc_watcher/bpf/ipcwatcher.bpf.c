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
/*!
\brief
    1. 简介
        本文件主要跟踪 Linux IPC 进程间通信的相关信息
        主要包括： unix domain socket（UDS）、mmap共享内存、信号
    uds部分：
        0. 功能：
            1. 跟踪并输出uds的基本信息，包括可选的发送与接收信息
            2. 跟踪uds从发送到接收的路径跟踪
                unix_xx_sendmsg --> VFS --> unix_xx_recvmsg 的路径跟踪
        1. 挂载点
            unix_dgram
                kprobe:unix_dgram_sendmsg
                kprobe:unix_dgram_recvmsg
                kprobe:unix_dgram_poll      [opt]
                kprobe:unix_dgram_connect   [opt]
            unix_stream
                kprobe:unix_stream_recvmsg
                kprobe:unix_stream_sendmsg
                kprobe:unix_stream_connect  [opt]
                
        2. 内核文件： net/unix/af_unix.c
    mmap shm：
        TODO
    signal：
        TODO
*/

#include "common.bpf.h"

// 获取UDS路径的辅助函数
static void get_uds_path(struct unix_sock *u, char *path) {
    struct unix_address *addr;
    struct sockaddr_un *sun;

    addr = BPF_CORE_READ(u, addr);
    if (!addr) {
        bpf_probe_read_kernel_str(path, 6, "<none>");
        return;
    }

    sun = BPF_CORE_READ(addr, name);
    if (!sun) {
        bpf_probe_read_kernel_str(path, 6, "<none>");
        return;
    }

    bpf_probe_read_kernel_str(path, sizeof(sun->sun_path), sun->sun_path);
}


/*!
\brief
    挂载点 unix_dgram_sendmsg, 负责采集uds dgram的基本信息与发送的数据
*/
SEC("kprobe/unix_dgram_sendmsg")
int BPF_KPROBE(unix_dgram_sendmsg, const struct socket *sock, const struct msghdr *msg,
			      size_t len) {
    // TODO
    return 0;
}

/*!
\brief
    挂载点 unix_dgram_recvmsg, 负责采集uds dgram的基本信息与接收的数据
*/
SEC("kprobe/unix_dgram_recvmsg")
int BPF_KPROBE(unix_dgram_recvmsg, const struct socket *sock, const struct msghdr *msg,
			      size_t size, int flags) {
    // TODO
    return 0;
}

/*!
\brief
    挂载点 unix_stream_sendmsg, 负责采集流式uds的基本信息与发送的数据
*/
SEC("kprobe/unix_stream_sendmsg")
int BPF_KPROBE(unix_stream_sendmsg, const struct socket *sock, const struct msghdr *msg,
			       size_t len) {
    struct uds_event event = {};
    struct sock *sk = BPF_CORE_READ(sock, sk);
    struct unix_sock *u = (struct unix_sock *)sk;

    event.pid = bpf_get_current_pid_tgid() >> 32;
    event.len = len;
    event.direction = 0;
    get_uds_path(u, event.path);

    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event, sizeof(event));
    return 0;

/*
    struct event *e;
    struct sockaddr_un *saddr, *daddr;
    struct sock *sk;
    u32 pid;

    sk = (struct sock *)sock->sk;
    if (!sk)
        return 0;

    if (sk->__sk_common.skc_family != AF_UNIX)
        return 0;

    pid = bpf_get_current_pid_tgid() >> 32;

    e = bpf_ringbuf_reserve(&uds_events, sizeof(*e), 0);
    if (!e)
        return 0;

    e->pid = pid;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    e->len = len;
    e->timestamp = bpf_ktime_get_ns();

    saddr = (struct sockaddr_un *)sk->saddr;
    daddr = (struct sockaddr_un *)sk->daddr;

    if (saddr) {
        e->saddr_len = saddr->sun_path[0] ? sizeof(struct sockaddr_un) : 0;
        if (e->saddr_len)
            bpf_probe_read_kernel(&e->saddr, sizeof(struct sockaddr_un), saddr);
    } else {
        e->saddr_len = 0;
    }

    if (daddr) {
        e->daddr_len = daddr->sun_path[0] ? sizeof(struct sockaddr_un) : 0;
        if (e->daddr_len)
            bpf_probe_read_kernel(&e->daddr, sizeof(struct sockaddr_un), daddr);
    } else {
        e->daddr_len = 0;
    }

    bpf_ringbuf_submit(e, 0);
    return 0;
    */
}

/*!
\brief
    挂载点 unix_stream_recvmsg, 负责采集流式uds的基本信息与接收的数据
*/
SEC("kprobe/unix_stream_recvmsg")
int BPF_KPROBE(unix_stream_recvmsg, const struct socket *sock, const struct msghdr *msg,
			       size_t size, int flags) {
    struct uds_event event = {};
    struct sock *sk = BPF_CORE_READ(sock, sk);
    struct unix_sock *u = (struct unix_sock *)sk;

    event.pid = bpf_get_current_pid_tgid() >> 32;
    event.len = size;
    event.direction = 1;
    get_uds_path(u, event.path);

    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event, sizeof(event));
    return 0;



    /*
    struct event *e;
    struct sockaddr_un *saddr, *daddr;
    struct sock *sk;
    u32 pid;

    sk = (struct sock *)ctx->skaddr;
    if (!sk)
        return 0;

    if (sk->__sk_common.skc_family != AF_UNIX)
        return 0;

    pid = bpf_get_current_pid_tgid() >> 32;
    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;

    e->pid = pid;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    e->len = ctx->size;
    e->ts = bpf_ktime_get_ns();

    saddr = (struct sockaddr_un *)ctx->saddr;
    daddr = (struct sockaddr_un *)ctx->daddr;

    if (saddr) {
        e->saddr_len = saddr->sun_path[0] ? sizeof(struct sockaddr_un) : 0;
        if (e->saddr_len)
            bpf_probe_read_kernel(&e->saddr, sizeof(struct sockaddr_un), saddr);
    } else {
        e->saddr_len = 0;
    }

    if (daddr) {
        e->daddr_len = daddr->sun_path[0] ? sizeof(struct sockaddr_un) : 0;
        if (e->daddr_len)
            bpf_probe_read_kernel(&e->daddr, sizeof(struct sockaddr_un), daddr);
    } else {
        e->daddr_len = 0;
    }

    bpf_ringbuf_submit(e, 0);
    return 0;
    */
}

char LICENSE[] SEC("license") = "GPL";
