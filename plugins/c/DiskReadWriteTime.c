#include <uapi/linux/ptrace.h>
#include <linux/blkdev.h>
struct val_t {
    u32 pid;
    char name[TASK_COMM_LEN];
    u64 ts;
};
struct data_t {
    u32 pid;
    u64 rwflag;
    u64 delta;
    u64 sector;
    u64 len;
    u64 ts;
    char disk_name[DISK_NAME_LEN];
    char name[TASK_COMM_LEN];
};
BPF_HASH(infobyreq, struct request *, struct val_t);
BPF_PERF_OUTPUT(events);
// cache PID and comm by-req
int trace_pid_start(struct pt_regs *ctx, struct request *req)
{
    struct val_t val = {};
    if (bpf_get_current_comm(&val.name, sizeof(val.name)) == 0) {
        val.pid = bpf_get_current_pid_tgid();
        val.ts = bpf_ktime_get_ns();
        infobyreq.update(&req, &val);
    }
    return 0;
}
// output
int trace_req_completion(struct pt_regs *ctx, struct request *req)
{
    u64 delta;
    u32 *pidp = 0;
    struct val_t *valp;
    struct data_t data = {};
    u64 ts;
    // fetch timestamp and calculate delta
    ts = bpf_ktime_get_ns();
    //if(data.delta < 1000000){
    //   return 0;
    //}
    valp = infobyreq.lookup(&req);
    //data.delta = ts - valp->ts;
    data.ts = ts/1000;
    if (valp == 0) {
        data.len = req->__data_len;
        strcpy(data.name, "?");
    } else {
        data.delta = ts - valp->ts;
        data.pid = valp->pid;
        data.len = req->__data_len;
        data.sector = req->__sector;
        bpf_probe_read(&data.name, sizeof(data.name), valp->name);
        struct gendisk *rq_disk = req->rq_disk;
        bpf_probe_read(&data.disk_name, sizeof(data.disk_name),
                       rq_disk->disk_name);
    }
#ifdef REQ_WRITE
    data.rwflag = !!(req->cmd_flags & REQ_WRITE);
#elif defined(REQ_OP_SHIFT)
    data.rwflag = !!((req->cmd_flags >> REQ_OP_SHIFT) == REQ_OP_WRITE);
#else
    data.rwflag = !!((req->cmd_flags & REQ_OP_MASK) == REQ_OP_WRITE);
#endif
    events.perf_submit(ctx, &data, sizeof(data));
    infobyreq.delete(&req);
    return 0;
}