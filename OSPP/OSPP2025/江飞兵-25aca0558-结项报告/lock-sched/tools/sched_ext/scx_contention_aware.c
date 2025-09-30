// scx_contention_aware.c
#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <libgen.h>
#include <bpf/bpf.h>
#include <scx/common.h>
#include "scx_contention_aware.bpf.skel.h"

static volatile int exit_req;

static void sigint_handler(int sig) {
	exit_req = 1;
}

int main(int argc, char **argv) {
	struct scx_contention_aware *skel;
	struct bpf_link *link;
	__u64 ecode;

	signal(SIGINT, sigint_handler);
	signal(SIGTERM, sigint_handler);
	
	skel = SCX_OPS_OPEN(ops, scx_contention_aware);
    if (!skel) {
        fprintf(stderr, "Failed to open BPF skeleton\n");
        return 1;
    }
	
	SCX_OPS_LOAD(skel, ops, scx_contention_aware, uei);
	link = SCX_OPS_ATTACH(skel, ops, scx_contention_aware);
    if (!link) {
        fprintf(stderr, "Failed to attach BPF skeleton\n");
        // 关键修正: 使用正确的函数名 scx_contention_aware__destroy
        scx_contention_aware__destroy(skel);
        return 1;
    }

	printf("Contention-aware scheduler attached. Monitoring... Press Ctrl-C to exit.\n");

	while (!exit_req && !UEI_EXITED(skel, uei)) {
		sleep(1);
	}

	bpf_link__destroy(link);
	ecode = UEI_REPORT(skel, uei);
    // 关键修正: 使用正确的函数名 scx_contention_aware__destroy
	scx_contention_aware__destroy(skel);
	
	if (UEI_ECODE_RESTART(ecode))
		return 1;
	return 0;
}