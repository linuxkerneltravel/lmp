#include <uapi/linux/ptrace.h>
#include <net/sock.h>
#include <bcc/proto.h>
#include <linux/string.h>
#define CONTAINER_ID_LEN 128

struct ipv4_key_t {
    u32 pid;
    u32 saddr;
    u32 daddr;
    u16 lport;
    u16 dport;
    char task[TASK_COMM_LEN];
    char container_id[CONTAINER_ID_LEN];
};
BPF_HASH(ipv4_send_bytes, struct ipv4_key_t);
BPF_HASH(ipv4_recv_bytes, struct ipv4_key_t);

int kprobe__udp_sendmsg(struct pt_regs *ctx, struct sock *sk,
    struct msghdr *msg, size_t size)
{       char container_id[CONTAINER_ID_LEN]="0"; //容器id初始化
        struct task_struct *curr_task;
        struct css_set *css;
        struct cgroup_subsys_state *sbs;
        struct cgroup *cg;
        struct kernfs_node *knode, *pknode;
        curr_task = (struct task_struct *) bpf_get_current_task();
        css = curr_task->cgroups;
        bpf_probe_read(&sbs, sizeof(void *), &css->subsys[0]);
        bpf_probe_read(&cg,  sizeof(void *), &sbs->cgroup);
        bpf_probe_read(&knode, sizeof(void *), &cg->kn);
        bpf_probe_read(&pknode, sizeof(void *), &knode->parent);
        if(pknode != NULL) {
          char *aus;
          bpf_probe_read(&aus, sizeof(void *), &knode->name);
          bpf_probe_read_str(container_id, CONTAINER_ID_LEN, aus);
          }
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u16 dport = 0, family = sk->__sk_common.skc_family;

    if (family == AF_INET) {
        //bpf_probe_read(&ipv4_key.saddr, sizeof(ipv4_key.saddr), &sk->__sk_common.skc_rcv_saddr);
        struct ipv4_key_t ipv4_key = {.pid = pid};
        bpf_get_current_comm(&ipv4_key.task, sizeof(ipv4_key.task));
        bpf_probe_read_str(&ipv4_key.container_id,CONTAINER_ID_LEN,container_id);
        ipv4_key.saddr = sk->__sk_common.skc_rcv_saddr;
        ipv4_key.daddr = sk->__sk_common.skc_daddr;
        ipv4_key.lport = sk->__sk_common.skc_num;
        dport = sk->__sk_common.skc_dport;
        ipv4_key.dport = ntohs(dport);
        ipv4_send_bytes.increment(ipv4_key, size);

    }
    return 0;
}
int kprobe__udp_recvmsg(struct pt_regs *ctx, struct sock *sk, int copied)
{
        char container_id[CONTAINER_ID_LEN]="0"; //容器id初始化
        struct task_struct *curr_task;
        struct css_set *css;
        struct cgroup_subsys_state *sbs;
        struct cgroup *cg;
        struct kernfs_node *knode, *pknode;
        curr_task = (struct task_struct *) bpf_get_current_task();
        css = curr_task->cgroups;
        bpf_probe_read(&sbs, sizeof(void *), &css->subsys[0]);
        bpf_probe_read(&cg,  sizeof(void *), &sbs->cgroup);
        bpf_probe_read(&knode, sizeof(void *), &cg->kn);
        bpf_probe_read(&pknode, sizeof(void *), &knode->parent);
        if(pknode != NULL) {
          char *aus;
          bpf_probe_read(&aus, sizeof(void *), &knode->name);
          bpf_probe_read_str(container_id, CONTAINER_ID_LEN, aus);
          }
    u32 pid = bpf_get_current_pid_tgid() >> 32;

    u16 dport = 0, family = sk->__sk_common.skc_family;
    u64 *val, zero =0;

    if (copied <= 0)
        return 0;

    if (family == AF_INET) {
        struct ipv4_key_t ipv4_key = {.pid = pid};
        bpf_get_current_comm(&ipv4_key.task, sizeof(ipv4_key.task));
        bpf_probe_read_str(&ipv4_key.container_id,CONTAINER_ID_LEN,container_id);
        ipv4_key.saddr = sk->__sk_common.skc_rcv_saddr;
        ipv4_key.daddr = sk->__sk_common.skc_daddr;
        ipv4_key.lport = sk->__sk_common.skc_num;
        dport = sk->__sk_common.skc_dport;
        ipv4_key.dport = ntohs(dport);
        ipv4_recv_bytes.increment(ipv4_key, copied);
    }
    return 0;
}
