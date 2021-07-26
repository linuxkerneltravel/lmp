#include <uapi/linux/ptrace.h>
#include <net/sock.h>
#include <bcc/proto.h>
#define CONTAINER_ID_LEN 128
#include <linux/string.h>
//创建保存sockeet指针的哈希
BPF_HASH(currsock, u32, struct sock *);

// separate data structs for ipv4 and ipv6
//记录ipv4_tcp连接信息的结构体
struct ipv4_data_t {
    u64 ts_us;
    u32 pid;
    u32 uid;
    u32 saddr;
    u32 daddr;
    u64 ip;
    u16 dport;
    char task[TASK_COMM_LEN];
    char container_id[CONTAINER_ID_LEN];
};
//创建ipv4_tcp连接的输出
BPF_PERF_OUTPUT(ipv4_events);

//创建ipv6_tcp连接信息的结构体
struct ipv6_data_t {
    u64 ts_us;
    u32 pid;
    u32 uid;
    unsigned __int128 saddr;
    unsigned __int128 daddr;
    u64 ip;
    u16 dport;
    char task[TASK_COMM_LEN];
    char container_id[CONTAINER_ID_LEN];
};
//创建ipv6_tcp连接的输出
BPF_PERF_OUTPUT(ipv6_events);

// separate flow keys per address family

//在进入tcp_v4_connect时调用
int trace_connect_entry(struct pt_regs *ctx, struct sock *sk)
{
    if (container_should_be_filtered()) {
        return 0;
    }

    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    u32 tid = pid_tgid;
    FILTER_PID

    u32 uid = bpf_get_current_uid_gid();
    FILTER_UID

    currsock.update(&tid, &sk);//使用tid作为key,保存sk指针指向的地址

    return 0;
}
//在从tcp_v4_connect返回时调用
static int trace_connect_return(struct pt_regs *ctx, short ipver)
{
    int ret = PT_REGS_RC(ctx);//获取tcp_v4_connect函数的返回值
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    u32 tid = pid_tgid;


    struct sock **skpp;
    skpp = currsock.lookup(&tid);//判断当前线程在进入tcp_v4_connect时是否打点采集
    if (skpp == 0) {
        return 0;   // missed entry
    }

    if (ret != 0) {  //tcp_v4_connect返回值非0，没有发送syn报文
        currsock.delete(&tid); //采集失败，删除哈希
        return 0;
    }

    // pull in details
    struct sock *skp = *skpp;
    u16 dport = skp->__sk_common.skc_dport;//获取到目的端口号

    FILTER_PORT
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
    if (ipver == 4) {
        struct ipv4_data_t data4 = {.pid = pid, .ip = ipver};
               data4.uid = bpf_get_current_uid_gid();
               data4.ts_us = bpf_ktime_get_ns() / 1000;
               data4.saddr = skp->__sk_common.skc_rcv_saddr;
               data4.daddr = skp->__sk_common.skc_daddr;
               data4.dport = ntohs(dport);
               bpf_get_current_comm(&data4.task, sizeof(data4.task));
               bpf_probe_read_str(&data4.container_id,CONTAINER_ID_LEN,container_id);
               ipv4_events.perf_submit(ctx, &data4, sizeof(data4));
    } else /* 6 */ {
         struct ipv6_data_t data6 = {.pid = pid, .ip = ipver};
               data6.uid = bpf_get_current_uid_gid();
               data6.ts_us = bpf_ktime_get_ns() / 1000;
               bpf_probe_read_kernel(&data6.saddr, sizeof(data6.saddr),
                   skp->__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32);
               bpf_probe_read_kernel(&data6.daddr, sizeof(data6.daddr),
                   skp->__sk_common.skc_v6_daddr.in6_u.u6_addr32);
               data6.dport = ntohs(dport);
               bpf_get_current_comm(&data6.task, sizeof(data6.task));
               bpf_probe_read_str(&data6.container_id,CONTAINER_ID_LEN,container_id);
               ipv6_events.perf_submit(ctx, &data6, sizeof(data6));


    }

    currsock.delete(&tid);

    return 0;
}

int trace_connect_v4_return(struct pt_regs *ctx)
{
    return trace_connect_return(ctx, 4);
}

int trace_connect_v6_return(struct pt_regs *ctx)
{
    return trace_connect_return(ctx, 6);
}