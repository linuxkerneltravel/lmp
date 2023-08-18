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
    bpf_printk("dest: %08x:%04x", ori_dst_ip, ori_dst_port);
    bpf_printk("1. Service backend ID (must be zero): %d", svc->backend_id);

    // 2. find backend slots from service
    // TODO: provide more (lightweight) selection logic later
    int keep_possibility = MAX_BACKEND_SELECTION;
    for (int i = 1; i <= MAX_BACKEND_SELECTION; i++) {
        if(i > svc->count)
            return -ENETRESET;

        key.backend_slot = i;
        backend_slot = lookup_lb4_backend_slot(&key);
        if (!backend_slot)
            return -ENOENT;

        u32 random_value = bpf_get_prandom_u32();
        bpf_printk("evaluate: %d < %d ? remain: %d", random_value % keep_possibility, backend_slot->possibility, keep_possibility);

        if((random_value % keep_possibility) < backend_slot->possibility) {
            key.backend_slot = i;
            break;
        }

        keep_possibility -= backend_slot->possibility;
        if(keep_possibility < 0)
            return -ENOENT;
    }

//    // 2. find backend slots from service
//    key.backend_slot = sock_select_random_slot(svc->count);

    bpf_printk("2. select backend from service slot: %d", key.backend_slot);

    // 3. lookup backend slot from constructed backend key
    backend_slot = lookup_lb4_backend_slot(&key);
    if (!backend_slot)
        return -ENOENT;
    bpf_printk("3. find backend slot: %d", backend_slot->backend_id);
    backend_id = backend_slot->backend_id;

    // 4. find the info of real backend
    backend = lookup_lb4_backend(backend_id);
    if (!backend)
        return -ENOENT;
    bpf_printk("4. real backend: %x", backend->address);

    // 5. got the address and port
    bpf_printk("verdict: %08x:%04x", backend->address, backend->port);
    ctx_set_dst_ip(ctx, backend->address);
    ctx_set_dst_port(ctx, backend->port);

    print_ip_formatted(ctx->user_ip4);

    return 0;
}

SEC("cgroup/connect4")
int sock4_connect(struct bpf_sock_addr *ctx)
{
    int ret = sock4_forward_entry(ctx);
    if(ret)
        bpf_printk("skipped, not modified");
    return SYS_PROCEED;
}

char _license[] SEC("license") = "GPL";
