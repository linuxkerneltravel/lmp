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
// author: Woa <me@wuzy.cn>

// +build ignore

#include "connect.h"

const __be32 service_ip = 0x846F070A;   // 10.7.111.132
const __be32 pod_ip     = 0x0100007F;   // 127.0.0.1
const __be16 service_port = 0x5000;     // 80   (0x0  * 256 + 0x50)
const __be16 pod_port     = 0x901f;     // 8080 (0x1f * 256 + 0x144)

static int sock4_forward_entry(struct bpf_sock_addr *ctx)
{
    // 0x846F070A;   // 10.7.111.132
    // 0x0529050A;   // 10.5.41.5
    // 0x0100007F;   // 127.0.0.1

    struct lb4_key key = {}, orig_key;    // must init the struct by zero
    struct lb4_service *svc;
    struct lb4_service *backend_slot;
    int backend_id = -1;
    struct lb4_backend *backend;

    __be32 ori_dst_ip   = ctx_get_dst_ip(ctx);
    __be16 ori_dst_port = ctx_get_dst_port(ctx);
    key.address = ori_dst_ip,
    key.dport = ori_dst_port,
    key.backend_slot = 0,
    orig_key = key;

    // 1. find service by ip and port
    svc = lb4_lookup_service(&key);
    if (!svc || svc->count == 0)
        return -ENXIO;

    // bpf_printk("dest: %08x:%04x", ori_dst_ip, ori_dst_port);
    // bpf_printk("1. Service backend ID (must be zero): %d", svc->backend_id);

    // 2. find backend slots from service
    if(svc->action == SVC_ACTION_NORMAL) {  // default action
        key.backend_slot = sock_select_random_slot(svc->count);
    } else if(svc->action == SVC_ACTION_WEIGHT) {
        int slot_index = sock_fast_select_weighted_slot(svc->count, key);
        if(slot_index < 0)
            return slot_index;
        key.backend_slot = slot_index;
    } else if(svc->action & SVC_ACTION_REDIRECT_SVC) {
        int slot_index = sock_fast_select_weighted_slot(svc->count + 1, key);
        if(slot_index > svc->count) {
            key.backend_slot = slot_index;
            // 3. lookup backend slot from constructed backend key
            backend_slot = lookup_lb4_backend_slot(&key);
            if (!backend_slot)
                return -ENOENT;
            // bpf_printk("3.5. find backend slot: %d", backend_slot->backend_id);
            backend_id = backend_slot->backend_id;

            // 4. find the info of real backend
            backend = lookup_lb4_backend(backend_id);
            if (!backend)
                return -ENOENT;
            key.backend_slot = 0;
            key.address = backend->address;
            key.dport = backend->port;
            slot_index = sock_fast_select_weighted_slot(svc->count, key);
            if(slot_index < 0)
                return slot_index;
            key.backend_slot = slot_index;
        } else {
            if(slot_index < 0)
                return slot_index;
            key.backend_slot = slot_index;
        }
    } else {
        bpf_printk("?, %d", svc->action);
        return -1;
    }
    // bpf_printk("2. select backend from service slot: %d", key.backend_slot);

    // 3. lookup backend slot from constructed backend key
    backend_slot = lookup_lb4_backend_slot(&key);
    if (!backend_slot)
        return -ENOENT;
    // bpf_printk("3. find backend slot: %d", backend_slot->backend_id);
    backend_id = backend_slot->backend_id;

    // 4. find the info of real backend
    backend = lookup_lb4_backend(backend_id);
    if (!backend)
        return -ENOENT;
    // bpf_printk("4. real backend: %x", backend->address);

    // 5. got the address and port
    // bpf_printk("verdict: %08x:%04x", backend->address, backend->port);
    ctx_set_dst_ip(ctx, backend->address);
    ctx_set_dst_port(ctx, backend->port);

    // print_ip_formatted(ctx->user_ip4);

    return 0;
}

SEC("cgroup/connect4")
int sock4_connect(struct bpf_sock_addr *ctx)
{
    // int ret =
    sock4_forward_entry(ctx);
    // if(ret)
    //     bpf_printk("skipped, not modified");
    return SYS_PROCEED;
}

char _license[] SEC("license") = "GPL";
