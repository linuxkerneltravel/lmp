#include <stdio.h>
#include <unistd.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include <signal.h>

#include "fs/fs_watcher/open.skel.h"	//包含了 BPF 字节码和相关的管理函数
#include "fs_watcher/include/open.h"

static volatile bool exiting = false;

static void sig_handler(int sig)
{
	exiting = true;
}

static int handle_event(void *ctx, void *data,unsigned long data_sz)
{
	const struct fs_t *e = data;
	printf("pid:%d uid:%llu time:%llu fd:%d comm:%s\n",e->pid,e->uid,e->ts,e->fd,e->comm);
	
	return 0;
}
	

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	return vfprintf(stderr, format, args);
}

int main(int argc, char **argv)
{
	struct ring_buffer *rb = NULL;
	struct open_bpf *skel;
	int err;

	libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
	/* 设置libbpf错误和调试信息回调 */
	libbpf_set_print(libbpf_print_fn);

	/* 更干净地处理Ctrl-C
	   SIGINT：由Interrupt Key产生，通常是CTRL+C或者DELETE。发送给所有ForeGround Group的进程
       SIGTERM：请求中止进程，kill命令发送
	*/
	signal(SIGINT, sig_handler);		//signal设置某一信号的对应动作
	signal(SIGTERM, sig_handler);

	/* 打开BPF应用程序 */
	skel = open_bpf__open();
	if (!skel) {
		fprintf(stderr, "Failed to open BPF skeleton\n");
		return 1;
	}
	
	/* 加载并验证BPF程序 */
	err = open_bpf__load(skel);
	if (err) {
		fprintf(stderr, "Failed to load and verify BPF skeleton\n");
		goto cleanup;
	}
	
	/* 附加跟踪点处理程序 */
	err = open_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "Failed to attach BPF skeleton\n");
		goto cleanup;
	}
	
	/* 设置环形缓冲区轮询 */
	rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_event, NULL, NULL);	//ring_buffer__new() API，允许在不使用额外选项数据结构下指定回调
	if (!rb) {
		err = -1;
		fprintf(stderr, "Failed to create ring buffer\n");
		goto cleanup;
	}
	
	/* 处理事件 */
	while (!exiting) {
		err = ring_buffer__poll(rb, 100 /* timeout, ms */);		//ring_buffer__poll(),轮询打开ringbuf缓冲区。如果有事件，handle_event函数会执行
		/* Ctrl-C will cause -EINTR */
		if (err == -EINTR) {
			err = 0;
			break;
		}
		if (err < 0) {
			printf("Error polling perf buffer: %d\n", err);
			break;
		}
		
		//exiting = true;			//使用该程序时,将该行代码注释掉 
		
	}
	
/* 卸载BPF程序 */
cleanup:
	ring_buffer__free(rb);
	open_bpf__destroy(skel);
	
	return err < 0 ? -err : 0;
}
