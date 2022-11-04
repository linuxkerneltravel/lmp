#include <stdio.h>
#include <unistd.h>
#include <sys/resource.h>
//#include <libbpf.h>
#include <bpf/libbpf.h>
#include "lsm.skel.h"

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
    return vfprintf(stderr, format, args);
}

int main(int argc, char *argv[])
{
    struct lsm_bpf *skel;
    int err;

    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
    libbpf_set_print(libbpf_print_fn);

    // Loads and verifies the BPF program
    skel = lsm_bpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "failed to load and verify BPF skeleton\n");
        goto cleanup;
    }
    skel->bss->my_pid = getpid();
    skel->bss->my_filename =  argv[1];
    printf("my_filename is %s \n ", skel->bss->my_filename);

    // Attaches the loaded BPF program to the LSM hook
    err = lsm_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "failed to attach BPF skeleton\n");
        goto cleanup;
    }

    printf("LSM loaded! ctrl+c to exit.\n");

    // The BPF link is not pinned, therefore exiting will remove program
    for (;;) {
        fprintf(stderr, ".");
        sleep(1);
    }

cleanup:
    lsm_bpf__destroy(skel);
    return err;
}
