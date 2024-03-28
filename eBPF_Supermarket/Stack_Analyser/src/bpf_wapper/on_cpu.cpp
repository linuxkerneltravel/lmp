// Copyright 2024 The LMP Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// https://github.com/linuxkerneltravel/lmp/blob/develop/LICENSE
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// author: luiyanbing@foxmail.com
//
// on cpu ebpf程序的包装类，实现接口和一些自定义方法

#include "bpf_wapper/on_cpu.h"
#include <sys/syscall.h>
#include <linux/perf_event.h>

/// @brief staring perf event
/// @param hw_event attribution of the perf event
/// @param pid the pid to track. 0 for the calling process. -1 for all processes.
/// @param cpu the cpu to track. -1 for all cpu
/// @param group_fd fd of event group leader
/// @param flags setting
/// @return fd of perf event
static long perf_event_open(struct perf_event_attr *hw_event, pid_t pid, int cpu, int group_fd,
                            unsigned long flags)
{
    return syscall(SYS_perf_event_open, hw_event, pid, cpu, group_fd, flags);
}

extern "C"
{
    extern int parse_cpu_mask_file(const char *fcpu, bool **mask, int *mask_sz);
}

OnCPUStackCollector::OnCPUStackCollector()
{
    setScale(freq);
};

void OnCPUStackCollector::setScale(uint64_t freq)
{
    this->freq = freq;
    scale.Period = 1e9 / freq;
    scale.Type = "OnCPUTime";
    scale.Unit = "nanoseconds";
}

double OnCPUStackCollector::count_value(void *data)
{
    return *(uint32_t *)data;
};

int OnCPUStackCollector::load(void)
{
    FILE *fp = popen("cat /proc/kallsyms | grep \" avenrun\"", "r");
    CHECK_ERR(!fp, "Failed to draw flame graph");
    unsigned long *load_a;
    fscanf(fp, "%p", &load_a);
    pclose(fp);
    StackProgLoadOpen(skel->rodata->load_a = load_a;);

    return 0;
};

int OnCPUStackCollector::attach(void)
{
    const char *online_cpus_file = "/sys/devices/system/cpu/online";
    bool *online_mask;
    int num_online_cpus;
    err = parse_cpu_mask_file(online_cpus_file, &online_mask, &num_online_cpus);
    CHECK_ERR(err, "Fail to get online CPU numbers");

    num_cpus = libbpf_num_possible_cpus();
    CHECK_ERR(num_cpus <= 0, "Fail to get the number of processors");

    struct perf_event_attr attr = {
        .type = PERF_TYPE_SOFTWARE, // hardware event can't be used
        .size = sizeof(attr),
        .config = PERF_COUNT_SW_CPU_CLOCK,
        .sample_freq = freq,
        .inherit = 1,
        .freq = 1, // use freq instead of period
    };
    pefds = (int *)malloc(num_cpus * sizeof(int));
    for (int i = 0; i < num_cpus; i++)
    {
        pefds[i] = -1;
    }
    links = (struct bpf_link **)calloc(num_cpus, sizeof(struct bpf_link *));
    for (int cpu = 0; cpu < num_cpus; cpu++)
    {
        /* skip offline/not present CPUs */
        if (cpu >= num_online_cpus || !online_mask[cpu])
        {
            continue;
        }
        /* Set up performance monitoring on a CPU/Core */
        int pefd = perf_event_open(&attr, pid, cpu, -1, 0);
        CHECK_ERR(pefd < 0, "Fail to set up performance monitor on a CPU/Core");
        pefds[cpu] = pefd;
        /* Attach a BPF program on a CPU */
        links[cpu] = bpf_program__attach_perf_event(skel->progs.do_stack, pefd); // 与内核bpf程序联系
        CHECK_ERR(!links[cpu], "Fail to attach bpf program");
    }
    return 0;
}

void OnCPUStackCollector::detach(void)
{
    if (links)
    {
        for (int cpu = 0; cpu < num_cpus; cpu++)
        {
            bpf_link__destroy(links[cpu]);
        }
        free(links);
        links = NULL;
    }
    if (pefds)
    {
        for (int i = 0; i < num_cpus; i++)
        {
            if (pefds[i] >= 0)
            {
                close(pefds[i]);
            }
        }
        free(pefds);
        pefds = NULL;
    }
};

void OnCPUStackCollector::unload(void)
{
    defaultUnload;
};
