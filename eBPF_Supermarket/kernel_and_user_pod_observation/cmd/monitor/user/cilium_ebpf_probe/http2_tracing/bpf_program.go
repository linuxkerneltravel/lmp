package http2_tracing

const bpfProgram = `
#include <uapi/linux/ptrace.h>

#define HEADER_FIELD_STR_SIZE 128
#define MAX_HEADER_COUNT 64

struct header_field_t {
  int32_t size;
  char msg[HEADER_FIELD_STR_SIZE];
};

struct go_grpc_http2_header_event_t {
  struct header_field_t name;
  struct header_field_t value;
};
struct write_header_t{
	struct go_grpc_http2_header_event_t event[2];
    int32_t sid;
	int64_t ns;
};
struct operator_header_t{
	struct go_grpc_http2_header_event_t event[8];
	int32_t sid;
    int8_t w;
	int64_t ns;
};
BPF_PERCPU_ARRAY(write_header_heap,struct write_header_t,1);
BPF_PERCPU_ARRAY(operator_header_heap,struct operator_header_t,1);
BPF_PERF_OUTPUT(write_header_events);
BPF_PERF_OUTPUT(operator_header_events);
BPF_HASH(timecount, u64, u64,1);
// This matches the golang string object memory layout. Used to help read golang string objects in BPF code.
struct gostring {
  const char* ptr;
  int64_t len;
};

static int64_t min(int64_t l, int64_t r) {
  return l < r ? l : r;
}

// Copy the content of a hpack.HeaderField object into header_field_t object.
static void copy_header_field(struct header_field_t* dst, const void* header_field_ptr) {
  struct gostring str = {};
  bpf_probe_read(&str, sizeof(str), header_field_ptr);
  if (str.len <= 0) {
    dst->size = 0;
    return;
  }
  dst->size = min(str.len, HEADER_FIELD_STR_SIZE);
  bpf_probe_read(dst->msg, dst->size, str.ptr);
}

static void submit_headers_for_writeheader(struct pt_regs* ctx, void* fields_ptr, int64_t fields_len,int32_t streamid){
	const size_t header_field_size = 40;
	int zero=0;

   bpf_trace_printk("write streamID %d ",streamid);
	struct write_header_t *e=write_header_heap.lookup(&zero);
	if (e==NULL){
		bpf_trace_printk("return");
		return;}
	
	int64_t keyZero=0;
	u64 *tsp = timecount.lookup(&keyZero);
	if (tsp!=0){ //if is the second bigger time
		e->ns=(int64_t)(bpf_ktime_get_ns());
		timecount.delete(&keyZero);
	}
	else{ //if the first smaller time
		u64 ts = bpf_ktime_get_ns();
		timecount.update(&keyZero,&ts);
		e->ns=0;
	}

	e->sid=streamid;
	for (size_t i = 0; i < 2; i++) {
		if (i >= fields_len) {
			continue;
		}
		const void* header_field_ptr = fields_ptr + i * header_field_size;
		copy_header_field(&(e->event[i].name), header_field_ptr);
		copy_header_field(&(e->event[i].value), header_field_ptr + 16);
		}
	write_header_events.perf_submit(ctx, e, sizeof(*e));    
}
static void submit_headers_for_operatorheader(struct pt_regs* ctx, void* fields_ptr, int64_t fields_len,int32_t streamid,int8_t weight){
	const size_t header_field_size = 40;

    bpf_trace_printk("streamID %d weight %d",streamid,weight);
	int zero=0;
	struct operator_header_t *e=operator_header_heap.lookup(&zero);
	if (e==NULL){
		bpf_trace_printk("return");
		return;}
	e->sid=streamid;
	e->w=weight;
	e->ns=bpf_ktime_get_ns();
	for (size_t i = 0; i < 8; i++) {
		if (i >= fields_len) {
			continue;
		}
		const void* header_field_ptr = fields_ptr + i * header_field_size;
		copy_header_field(&(e->event[i].name), header_field_ptr);
		copy_header_field(&(e->event[i].value), header_field_ptr + 16);
	}
	operator_header_events.perf_submit(ctx, e, sizeof(*e));
}

// Signature:2 + 2 func (l *loopyWriter) writeHeader(streamID uint32, endStream bool, hf []hpack.HeaderField, onWrite func())
int probe_loopy_writer_write_header(struct pt_regs* ctx) { 
  void* ptr=(void*)ctx->di;
  int64_t fields_len;
  fields_len=ctx->si;
  submit_headers_for_writeheader(ctx, ptr, fields_len,ctx->bx);
	
  return 0;
}

// Signature: 8 func (t *http2Server) operateHeaders(frame *http2.MetaHeadersFrame, handle func(*Stream),
// traceCtx func(context.Context, string) context.Context)
int probe_http2_server_operate_headers(struct pt_regs* ctx) {
  void* frame_ptr=(void*)ctx->bx;
  void* fields_ptr;
  bpf_probe_read(&fields_ptr, sizeof(void*), frame_ptr + 8);
  int64_t fields_len;
  bpf_probe_read(&fields_len, sizeof(int64_t), frame_ptr + 8 + 8);

  void* headersframe_ptr;
  bpf_probe_read(&headersframe_ptr,sizeof(void*),frame_ptr);
  int32_t streamid;
  bpf_probe_read(&streamid,sizeof(int32_t),headersframe_ptr+8);
  int8_t weight;
  bpf_probe_read(&weight,sizeof(int8_t),headersframe_ptr+17);

  submit_headers_for_operatorheader(ctx, fields_ptr, fields_len,streamid,weight);
  return 0;
}
`
