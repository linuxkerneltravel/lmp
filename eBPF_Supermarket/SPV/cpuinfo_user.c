#define _GNU_SOURCE

#include <assert.h>
#include <fcntl.h>
#include <linux/perf_event.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include "perf-sys.h"

#define SAMPLE_PERIOD 0x7fffffffffffffffULL

#define TIME_SLICE 1

enum perf_flag {
    FLAG_CPU_CYCLES,	/* CPU_CYCLES */
    FLAG_CPU_CLOCK,	/* CPU_CLOCK */
    FLAG_NUMS
};

/* 记录未完成的频段的起始信息 */
struct start_count {
    __u32 prev_freq;
    __u64 start_cyl;
    __u64 start_clk;
};

/* dvfs_key, 充当Map的键, 字段为CPU和频段 */
struct dvfs_key {
    __u32 cpu;
    __u32 freq;
};

/* dvfs_value, 充当Map的值, 字段为此CPU在此频段的CPU_CYCLES和CPU_CLOCK计数值 */
struct dvfs_value {
    __u64 cyl;
    __u64 clk;
};

static int map_fd[4];

static int pmufd_cyl[64];
static int pmufd_clk[64];

/* 注册对应的perf event，并将文件局部保存到pmufd_xx以及map_fd中 */
static void register_perf(int cpu, struct perf_event_attr *attr, enum perf_flag f) {
    switch (f) {
        case FLAG_CPU_CYCLES:
            pmufd_cyl[cpu] = sys_perf_event_open(attr, -1, cpu, -1, 0);

            ioctl(pmufd_cyl[cpu], PERF_EVENT_IOC_RESET, 0);
            ioctl(pmufd_cyl[cpu], PERF_EVENT_IOC_ENABLE, 0);

            bpf_map_update_elem(map_fd[0], &cpu, &(pmufd_cyl[cpu]), BPF_ANY);

            break;

        case FLAG_CPU_CLOCK:
            pmufd_clk[cpu] = sys_perf_event_open(attr, -1, cpu, -1, 0);

            ioctl(pmufd_clk[cpu], PERF_EVENT_IOC_RESET, 0);
            ioctl(pmufd_clk[cpu], PERF_EVENT_IOC_ENABLE, 0);

            bpf_map_update_elem(map_fd[1], &cpu, &(pmufd_clk[cpu]), BPF_ANY);
            
	    break;

        default:
            break;
    }
}

/* 打开对应的CPU目录,填充结构体start_count,并存入对应的start_info的map中 */
static void get_current_info(int cpu)
{
    struct start_count sc = {};

    FILE *fd;
    char filename[256], temp[32], buff[256], *ptr;

    sprintf(temp, "%d", cpu);
    snprintf(filename, sizeof(filename), "/sys/devices/system/cpu/cpu%s/cpufreq/scaling_cur_freq", temp);

    fd = fopen(filename, "r");
    fgets(buff, sizeof(buff), fd);

    /* 读取指定文件获得最开始的频率值 */
    sc.prev_freq = strtol(buff, &ptr, 10);

    /* 读取pmu文件获得当前的CPU_CYCLES和CPU_CLOCK */
    read(pmufd_cyl[cpu], &(sc.start_cyl), sizeof(sc.start_cyl));
    read(pmufd_clk[cpu], &(sc.start_clk), sizeof(sc.start_clk));

    /* 更新state_count到对应的map中 */
    bpf_map_update_elem(map_fd[2], &cpu, &sc, BPF_ANY);
}

int main(int argc, char **argv) {
    struct bpf_link *links[1];
    struct bpf_program *prog;
    struct bpf_object *obj;
    char filename[256];
    /* nr_cpus获得在线的CPU */
    int i, j, nr_cpus = sysconf(_SC_NPROCESSORS_ONLN);

    /* CPU_CYCLES的perf_event_attr信息 */
    struct perf_event_attr attr_cycles = {
        .freq = 0,
        .sample_period = SAMPLE_PERIOD,
        .inherit = 0,
        .type = PERF_TYPE_HARDWARE,
        .read_format = 0,
        .sample_type = 0,
        .config = PERF_COUNT_HW_CPU_CYCLES,
    };

    /* CPU_CLOCK的perf_event_attr信息 */
    struct perf_event_attr attr_clock = {
        .freq = 0,
        .sample_period = SAMPLE_PERIOD,
        .inherit = 0,
        .type = PERF_TYPE_SOFTWARE,
        .read_format = 0,
        .sample_type = 0,
        .config = PERF_COUNT_SW_CPU_CLOCK,
    };

    snprintf(filename, sizeof(filename), "%s_kern.o", argv[0]);
    obj = bpf_object__open_file(filename, NULL);
    if (libbpf_get_error(obj)) {
        fprintf(stderr, "ERROR: opending BPF object file failed\n");
        return 0;
    }

    if (bpf_object__load(obj)) {
        fprintf(stderr, "ERROR: loading BPF object failed\n");
        return -1;
    }

    /* 根据名字获得map句柄 */
    map_fd[0] = bpf_object__find_map_fd_by_name(obj, "pmu_cyl");
    map_fd[1] = bpf_object__find_map_fd_by_name(obj, "pmu_clk");
    map_fd[2] = bpf_object__find_map_fd_by_name(obj, "start_info");
    map_fd[3] = bpf_object__find_map_fd_by_name(obj, "cpudvfs_info");
    if (map_fd[0] < 0 || map_fd[1] < 0 || map_fd[2] < 0 || map_fd[3] < 0) {
        fprintf(stderr, "ERROR: finding a map in obj file failed\n");
        return -1;
    }

    /* 注册对应的perf event */
    for (j = 0; j < nr_cpus; j++) {
        register_perf(j, &attr_cycles, FLAG_CPU_CYCLES);
        register_perf(j, &attr_clock, FLAG_CPU_CLOCK);
    }

    /* 根据/sys/devices/system/cpu/cpuX/scaling_cur_freq的内容，填充初始信息 */
    for (j = 0; j < nr_cpus; j++) {
        get_current_info(j);
    }

    /* 挂载程序 */
    bpf_object__for_each_program(prog, obj) {
        links[i] = bpf_program__attach(prog);
        if (libbpf_get_error(links[i])) {
            fprintf(stderr, "ERROR: bpf_program__attach failed\n");
            links[i] = NULL;
            return 0;
        }
        i++;
    }

    __u64 cyl_now, clk_now, cyl_delta, clk_delta;
    struct start_count sc = {}, sc_new = {};
    struct dvfs_key dk = {};
    struct dvfs_value dv = {}, dv_new = {};

    while(1) {
        sleep(TIME_SLICE);

        /* 手动获得当前的CPU_CYCLES和CPU_CLOCK计数值,并更新对应cpu的start_info以及cpudvfs_info */
        for (j = 0; j < nr_cpus; j++) {

            read(pmufd_cyl[j], &(cyl_now), sizeof(cyl_now));
            read(pmufd_clk[j], &(clk_now), sizeof(clk_now));

            if (bpf_map_lookup_elem(map_fd[2], &j, &sc) != 0) {
                fprintf(stderr, "ERROR: bpf_map_lookup_elem in map_fd[2] error\n");
                return -1;
            }

            cyl_delta = cyl_now - sc.start_cyl;
            clk_delta = clk_now - sc.start_clk;

            if (cyl_delta <= 0 || clk_delta <= 0) {
                continue;
            }

            sc_new.prev_freq = dk.freq = sc.prev_freq;

            sc_new.start_cyl = cyl_now;
            sc_new.start_clk = clk_now;

	        dk.cpu = j;
            
	        bpf_map_update_elem(map_fd[2], &j, &sc_new, BPF_ANY);

            if (bpf_map_lookup_elem(map_fd[3], &dk, &dv) != 0) {
                cyl_delta += dv.cyl;
                clk_delta += dv.clk;
            }

            dv_new.cyl = cyl_delta;
            dv_new.clk = clk_delta;
            bpf_map_update_elem(map_fd[3], &dk, &dv_new, BPF_ANY); 
        }

        struct dvfs_key key = {}, next_key = {};
        struct dvfs_value value = {};

        /* 获得每个CPU的频段信息,并计算对应频段的利用率 */
        while (bpf_map_get_next_key(map_fd[3], &key, &next_key) == 0) {
            bpf_map_lookup_elem(map_fd[3], &next_key, &value);
            double util = value.cyl * 1000000.0 / (next_key.freq * value.clk);
            printf("CPU: %6d Freq: %16d Time: %16llu Cycles: %16llu Util: %6.2f\n", next_key.cpu, next_key.freq, value.clk, value.cyl, util);
            key = next_key;
            bpf_map_delete_elem(map_fd[3], &next_key);
        }
        printf("==============\n");
    }
    return 0;
}

