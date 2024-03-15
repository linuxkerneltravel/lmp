#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <signal.h>
#include <unistd.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include "memleak.skel.h"
#include "memleak.h"

#include "blazesym.h"

static const int perf_max_stack_depth = 127;    //stack id 对应的堆栈的深度
static const int stack_map_max_entries = 10240; //最大允许存储多少个stack_id
static __u64 *g_stacks = NULL;
static size_t g_stacks_size = 0;

static struct blaze_symbolizer *symbolizer;

static void print_frame(const char *name, uintptr_t input_addr, uintptr_t addr, uint64_t offset, const blaze_symbolize_code_info* code_info)
{
    // If we have an input address  we have a new symbol.
    if (input_addr != 0) {
      printf("%016lx: %s @ 0x%lx+0x%lx", input_addr, name, addr, offset);
			if (code_info != NULL && code_info->dir != NULL && code_info->file != NULL) {
				printf(" %s/%s:%u\n", code_info->dir, code_info->file, code_info->line);
      } else if (code_info != NULL && code_info->file != NULL) {
				printf(" %s:%u\n", code_info->file, code_info->line);
      } else {
				printf("\n");
      }
    } else {
      printf("%16s  %s", "", name);
			if (code_info != NULL && code_info->dir != NULL && code_info->file != NULL) {
				printf("@ %s/%s:%u [inlined]\n", code_info->dir, code_info->file, code_info->line);
      } else if (code_info != NULL && code_info->file != NULL) {
				printf("@ %s:%u [inlined]\n", code_info->file, code_info->line);
      } else {
				printf("[inlined]\n");
      }
    }
}

static void show_stack_trace(__u64 *stack, int stack_sz, pid_t pid) {
    const struct blaze_symbolize_inlined_fn *inlined;
    const struct blaze_result *result;
    const struct blaze_sym *sym;
    int i, j;

    assert(sizeof(uintptr_t) == sizeof(uint64_t));

    if (pid) {
        struct blaze_symbolize_src_process src = {
            .pid = pid,
        };
        result = blaze_symbolize_process(symbolizer, &src, (const uintptr_t *)stack, stack_sz);
    }
    else {
        struct blaze_symbolize_src_kernel src = {};
        result = blaze_symbolize_kernel(symbolizer, &src, (const uintptr_t *)stack, stack_sz);
    }


    for (i = 0; i < stack_sz; i++) {
        if (!result || result->cnt <= i || result->syms[i].name == NULL) {
            printf(" %2d [<%016llx>]\n", i, stack[i]);
            continue;
        }

        sym = &result->syms[i];
        print_frame(sym->name, stack[i], sym->addr, sym->offset, &sym->code_info);

        for (j = 0; j < sym->inlined_cnt; j++) {
            inlined = &sym->inlined[j];
            print_frame(sym->name, 0, 0, 0, &inlined->code_info);
        }
    }

    blaze_result_free(result);
}

int print_outstanding_combined_allocs(struct memleak_bpf *skel, pid_t pid) {
    const size_t combined_allocs_key_size = bpf_map__key_size(skel->maps.combined_allocs);
    const size_t stack_traces_key_size = bpf_map__key_size(skel->maps.stack_traces);

    for (__u64 prev_key = 0, curr_key = 0; ; prev_key = curr_key) {

        if (bpf_map__get_next_key(skel->maps.combined_allocs,
            &prev_key, &curr_key, combined_allocs_key_size)) {
            if (errno == ENOENT) {
                break; //no more keys, done!
            }
            perror("map get next key failed!");

            return -errno;
        }

        // stack_id = curr_key
        union combined_alloc_info cinfo;
        memset(&cinfo, 0, sizeof(cinfo));

        if (bpf_map__lookup_elem(skel->maps.combined_allocs,
            &curr_key, combined_allocs_key_size, &cinfo, sizeof(cinfo), 0)) {
            if (errno == ENOENT) {
                continue;
            }

            perror("map lookup failed!");
            return -errno;
        }

        if (bpf_map__lookup_elem(skel->maps.stack_traces,
            &curr_key, stack_traces_key_size, g_stacks, g_stacks_size, 0)) {
            perror("failed to lookup stack traces!");
            return -errno;
        }

        printf("stack_id=0x%llx with outstanding allocations: total_size=%llu nr_allocs=%llu\n",
            curr_key, (__u64)cinfo.total_size, (__u64)cinfo.number_of_allocs);

        int stack_sz = 0;
        for (int i = 0; i < perf_max_stack_depth; i++) {
            if (g_stacks[i] == 0) {
                break;
            }
            stack_sz++;
            //printf("[%3d] 0x%llx\n", i, g_stacks[i]);
        }

        show_stack_trace(g_stacks, stack_sz, pid);
    }

    return 0;
}

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
    return vfprintf(stderr, format, args);
}

int main(int argc, char **argv)
{
    struct memleak_bpf *skel;
    int err, i;
    LIBBPF_OPTS(bpf_uprobe_opts, uprobe_opts);
    int attach_pid;
    char binary_path[128] = {0};
 
    if (argc != 2)
    {
        printf("usage:%s attach_pid\n", argv[0]);
        return -1;
    }
 
    attach_pid = atoi(argv[1]);
    strcpy(binary_path, "/lib/x86_64-linux-gnu/libc.so.6");
 
    /* Set up libbpf errors and debug info callback */
    libbpf_set_print(libbpf_print_fn);

    /* Load and verify BPF application */
    skel = memleak_bpf__open();
    if (!skel) {
        fprintf(stderr, "Failed to open BPF skeleton\n");
        return 1;
    }
 
    bpf_map__set_value_size(skel->maps.stack_traces, perf_max_stack_depth * sizeof(__u64));
    bpf_map__set_max_entries(skel->maps.stack_traces, stack_map_max_entries);

    /* Load & verify BPF programs */
    err = memleak_bpf__load(skel);
    if (err) {
        fprintf(stderr, "Failed to load BPF skeleton\n");
        goto cleanup;
    }

    /* Attach tracepoint handler */
    uprobe_opts.func_name = "malloc";
    uprobe_opts.retprobe = false;
    /* uprobe/uretprobe expects relative offset of the function to attach
	 * to. libbpf will automatically find the offset for us if we provide the
	 * function name. If the function name is not specified, libbpf will try
	 * to use the function offset instead.
	 */
    skel->links.malloc_enter = bpf_program__attach_uprobe_opts(skel->progs.malloc_enter,
        attach_pid /* self pid */, binary_path,
        0 /* offset for function */,
        &uprobe_opts /* opts */);
    if (!skel->links.malloc_enter) {
        err = -errno;
        fprintf(stderr, "Failed to attach uprobe: %d\n", err);
        goto cleanup;
    }
 
    uprobe_opts.func_name = "malloc";
    uprobe_opts.retprobe = true;
    skel->links.malloc_exit = bpf_program__attach_uprobe_opts(skel->progs.malloc_exit,
        attach_pid, binary_path,
        0, &uprobe_opts);
    if (!skel->links.malloc_exit) {
        err = -errno;
        fprintf(stderr, "Failed to attach uprobe: %d\n", err);
        goto cleanup;
    }
 
    uprobe_opts.func_name = "free";
    uprobe_opts.retprobe = false;
    skel->links.free_enter = bpf_program__attach_uprobe_opts(skel->progs.free_enter,
        attach_pid, binary_path,
        0, &uprobe_opts);
    if (!skel->links.free_enter) {
        err = -errno;
        fprintf(stderr, "Failed to attach uprobe: %d\n", err);
        goto cleanup;
    }
 
    /* Let libbpf perform auto-attach for uprobe_sub/uretprobe_sub
     * NOTICE: we provide path and symbol info in SEC for BPF programs
     */
    err = memleak_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "Failed to auto-attach BPF skeleton: %d\n", err);
        goto cleanup;
    }
 
    g_stacks_size = perf_max_stack_depth * sizeof(*g_stacks);
    g_stacks = (__u64 *)malloc(g_stacks_size);
    memset(g_stacks, 0, g_stacks_size);

    symbolizer = blaze_symbolizer_new();
    if (!symbolizer) {
        fprintf(stderr, "Fail to create a symbolizer\n");
        err = -1;
        goto cleanup;
    }

    for (i = 0;; i++) {
        /* trigger our BPF programs */
        print_outstanding_combined_allocs(skel, attach_pid);
        sleep(1);
    }

cleanup:
    memleak_bpf__destroy(skel);
    blaze_symbolizer_free(symbolizer);
    free(g_stacks);
    return -err;
}
