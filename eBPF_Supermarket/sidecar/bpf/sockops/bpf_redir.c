// +build ignore

// ver: 796d738babee7da77815ad2819a69d37d8472dea
#include "vmlinux.h"
#include <bpf_helpers.h>
#include <bpf_endian.h>
#include "bpf_sockops.h"

SEC("sk_msg")
int bpf_redir_proxy(struct sk_msg_md *msg)
{
    uint32_t rc;
    uint32_t* debug_val_ptr;
    uint32_t debug_val;
    uint32_t debug_on_index = 0;
    uint32_t debug_pckts_index = 1;

    struct socket_4_tuple proxy_key = {};
    /* for inbound traffic */
    struct socket_4_tuple key = {};
    /* for outbound and envoy<->envoy traffic*/
    struct socket_4_tuple *key_redir = NULL;

    sk_msg_extract4_keys(msg, &proxy_key, &key);

    if (is_inbound_ip(key.local.ip4) || is_inbound_ip(key.remote.ip4)) { // local network, redirect directly
        rc = bpf_msg_redirect_hash(msg, &map_redir, &key, BPF_F_INGRESS); // use `key` to find the target skops
    } else {
        key_redir = bpf_map_lookup_elem(&map_proxy, &proxy_key); // use `proxy_key` to find the key of target skops
        if (key_redir == NULL) {
            return SK_PASS;
        }
        rc = bpf_msg_redirect_hash(msg, &map_redir, key_redir, BPF_F_INGRESS);
    }

    if (rc == SK_PASS) {
        debug_val_ptr = bpf_map_lookup_elem(&debug_map, &debug_on_index);
        if (debug_val_ptr && *debug_val_ptr == 1) {
            char info_fmt[] = "data redirection succeed: [%x]->[%x]\n";
            bpf_trace_printk(info_fmt, sizeof(info_fmt), proxy_key.local.ip4, proxy_key.remote.ip4);

            debug_val_ptr = bpf_map_lookup_elem(&debug_map, &debug_pckts_index);
            if (debug_val_ptr == NULL) {
                debug_val = 0;
                debug_val_ptr = &debug_val;
            }
            __sync_fetch_and_add(debug_val_ptr, 1);
            bpf_map_update_elem(&debug_map, &debug_pckts_index, debug_val_ptr, BPF_ANY);

        }
    }
    return SK_PASS;
}

char _license[] SEC("license") = "GPL";
