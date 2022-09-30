package http_kprobe

const bpfProgram = `
#include <linux/sched.h>
#include <uapi/linux/ptrace.h>
#include <uapi/linux/stat.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/stat.h>
#include <linux/socket.h>
struct addr_info_t {
  struct sockaddr *addr;
  size_t *addrlen;
};
#define MAX_MSG_SIZE 1024
BPF_PERF_OUTPUT(syscall_write_events);

struct syscall_write_event_t {

  struct attr_t {
    int event_type;
    int fd; 
    int bytes;
    int msg_size;
	u64 start_ns;
	u64 end_ns;
  } attr;
  char msg[MAX_MSG_SIZE];
};
const int kEventTypeSyscallAddrEvent = 1;
const int kEventTypeSyscallWriteEvent = 2;
const int kEventTypeSyscallCloseEvent = 3;

BPF_PERCPU_ARRAY(write_buffer_heap, struct syscall_write_event_t, 1);      

BPF_HASH(active_fds, int, bool);

BPF_HASH(active_sock_addr, u64, struct addr_info_t);

int syscall__probe_entry_accept4(struct pt_regs *ctx, int sockfd, struct sockaddr *addr, size_t *addrlen, int flags) {
  u64 id = bpf_get_current_pid_tgid();
  u32 pid = id >> 32;

  if (pid != $PID) {
      return 0;
  }
  struct addr_info_t addr_info;
  addr_info.addr = addr;
  addr_info.addrlen = addrlen;
  active_sock_addr.update(&id, &addr_info);
  return 0;
}

int syscall__probe_ret_accept4(struct pt_regs *ctx, int sockfd, struct sockaddr *addr, size_t *addrlen, int flags) {
  u64 id = bpf_get_current_pid_tgid();
  u32 pid = id >> 32;

  if (pid != $PID) {
      return 0;
  }
  struct addr_info_t* addr_info = active_sock_addr.lookup(&id);
  if (addr_info == NULL) {
    goto done;
  }

  int fd = PT_REGS_RC(ctx);
  if (fd < 0) {
    goto done;
  }
  bool t = true;
  active_fds.update(&fd, &t);
  int zero = 0;
  struct syscall_write_event_t *event = write_buffer_heap.lookup(&zero);
  if (event == 0) {
    goto done;
  }
  u64 addr_size = *(addr_info->addrlen);
  size_t buf_size = addr_size < sizeof(event->msg) ? addr_size : sizeof(event->msg);
  bpf_probe_read(&event->msg, buf_size, addr_info->addr);
  event->attr.event_type = kEventTypeSyscallAddrEvent;
  event->attr.fd = fd;
  event->attr.msg_size = buf_size;
  event->attr.bytes = buf_size;
  event->attr.start_ns = bpf_ktime_get_ns();
  event->attr.end_ns = 0;
  unsigned int size_to_submit = sizeof(event->attr) + buf_size;
  syscall_write_events.perf_submit(ctx, event, size_to_submit);
 done:
  active_sock_addr.delete(&id);
  return 0;
}
int syscall__probe_write(struct pt_regs *ctx, int fd, const void* buf, size_t count) {

  __u64 ts = bpf_ktime_get_ns();

  int zero = 0;
  struct syscall_write_event_t *event = write_buffer_heap.lookup(&zero);
  if (event == NULL) {
    return 0;
  }
  u64 id = bpf_get_current_pid_tgid();
  u32 pid = id >> 32;

  if (pid != $PID) {
      return 0;
  }
  if (active_fds.lookup(&fd) == NULL) {

    return 0;
  }
  event->attr.fd = fd;
  event->attr.bytes = count;
  size_t buf_size = count < sizeof(event->msg) ? count : sizeof(event->msg);
  bpf_probe_read(&event->msg, buf_size, (void*) buf);
  event->attr.msg_size = buf_size;
  unsigned int size_to_submit = sizeof(event->attr) + buf_size;
  event->attr.event_type = kEventTypeSyscallWriteEvent;


  syscall_write_events.perf_submit(ctx, event, size_to_submit);
  return 0;
}
int syscall__probe_close(struct pt_regs *ctx, int fd) {
  u64 id = bpf_get_current_pid_tgid();
  u32 pid = id >> 32;

  if (pid != $PID) {
      return 0;
  }
  int zero = 0;
  struct syscall_write_event_t *event = write_buffer_heap.lookup(&zero);
  if (event == NULL) {
    return 0;
  }
  
  event->attr.event_type = kEventTypeSyscallCloseEvent;
  event->attr.fd = fd;
  event->attr.bytes = 0;
  event->attr.msg_size = 0;
  event->attr.start_ns=0;
  event->attr.end_ns = bpf_ktime_get_ns();
  syscall_write_events.perf_submit(ctx, event, sizeof(event->attr));
  active_fds.delete(&fd);
  return 0;
}
`
