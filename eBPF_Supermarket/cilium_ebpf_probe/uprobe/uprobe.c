// +build ignore
//
#include "common.h"

#include "bpf_tracing.h"

char __license[] SEC("license") = "Dual MIT/GPL";
#define MSG_BUF_SIZE 128
#define URI_BUF_SIZE 64
#define METHOD_BUF_SIZE 8

struct event {
  u64 status_code;
  u64 uri_len;
  char uri[URI_BUF_SIZE];
  u64 method_len;
  char method[METHOD_BUF_SIZE];
  u64 msg_len;
  char msg[MSG_BUF_SIZE];
};
struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
} events SEC(".maps");
const struct event *unused __attribute__((unused));
SEC("uprobe/http_main")
int uprobe_ahttp_main(struct pt_regs *ctx) {
    struct event event = {};
    // Positions within stack frame:
    u64 struct_response_pos = 5;
    // Positions within struct response object:
    u64 req_ptr_pos = 1;
    u64 bufio_ptr_pos = 6;
    u64 content_length_pos = 13;
    u64 status_code_pos = 14;
    // Positions within struct request object:
    u64 method_ptr_pos = 0;
    u64 method_len_pos = 1;
    u64 uri_ptr_pos = 24;
    u64 uri_len_pos = 25;
    // Positions within bufio.Writer object:
    u64 buf_ptr_pos = 2;
    u64 array_ptr_pos = buf_ptr_pos + 0;
    u64 array_len_pos = buf_ptr_pos + 1;
    //------- Reponse struct information.
    // Read pointer to response struct (function's receiver, aka 'this' object).
    void* struct_response_ptr = NULL;
    bpf_probe_read(&struct_response_ptr, sizeof(struct_response_ptr), (void *)ctx->sp+(struct_response_pos*8));
    event.msg_len = (u64)struct_response_ptr;
    //------- Request pointer information.
    // Read req pointer from response struct.
    void* req_ptr = NULL;
    bpf_probe_read(&req_ptr, sizeof(req_ptr), struct_response_ptr+(req_ptr_pos*8));
    // Read bufio pointer from response struct.
    void* bufio_ptr = NULL;
    bpf_probe_read(&bufio_ptr, sizeof(bufio_ptr), struct_response_ptr+(bufio_ptr_pos*8));
    // Read status code from response struct.
    bpf_probe_read(&event.status_code, sizeof(event.status_code), struct_response_ptr+(status_code_pos*8));
    // Read bufio pointer from response struct.
    u64 content_length = 0;
    bpf_probe_read(&content_length, sizeof(content_length), struct_response_ptr+(content_length_pos*8));
    //------- Method pointer information.
    // Read array pointer from buf object.
    void* method_ptr = 0;
    bpf_probe_read(&method_ptr, sizeof(method_ptr), req_ptr+(method_ptr_pos*8));
    // Read array length from buf object.
    u64 method_len = 0;
    bpf_probe_read(&method_len, sizeof(method_len), req_ptr+(method_len_pos*8));
    // Read array from array pointer object.
    u64 method_buf_size = sizeof(event.method);
    method_buf_size = method_buf_size < method_len ? method_buf_size : method_len;
    bpf_probe_read(&event.method, method_buf_size, method_ptr);
    event.method_len = (u64)method_len;
    //------- URI Pointer information.
    // Read URI pointer from buf object.
    void* uri_ptr = 0;
    bpf_probe_read(&uri_ptr, sizeof(uri_ptr), req_ptr+(uri_ptr_pos*8));
    // Read URL length from buf object.
    u64 uri_len = 0;
    bpf_probe_read(&uri_len, sizeof(uri_len), req_ptr+(uri_len_pos*8));
    // Read URI from URI pointer object.
    u64 uri_buf_size = sizeof(event.uri);
    uri_buf_size = uri_buf_size < uri_len ? uri_buf_size : uri_len;
    bpf_probe_read(&event.uri, uri_buf_size, uri_ptr);
    event.uri_len = (u64)uri_buf_size;
    //------- Array information.
    // Read array pointer from buf object.
    void* array_ptr = 0;
    bpf_probe_read(&array_ptr, sizeof(array_ptr), bufio_ptr+(array_ptr_pos*8));
    // Read array length from buf object.
    u64 array_len = 0;
    bpf_probe_read(&array_len, sizeof(array_len), bufio_ptr+(array_len_pos*8));
    // Read array from array pointer object.
    u64 msg_buf_size = sizeof(event.msg);
    msg_buf_size = msg_buf_size < array_len ? msg_buf_size : array_len;
    bpf_probe_read(&event.msg, msg_buf_size, array_ptr);
    // Write snooped arguments to perf ring buffer.


    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event, sizeof(event));
    return 0;
}