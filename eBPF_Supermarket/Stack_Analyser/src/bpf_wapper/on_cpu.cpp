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
    scale_num = 1;
    scales = new Scale[scale_num]{
        {"OnCPUTime", (uint64_t)(1e9 / freq), "nanoseconds"},
    };
};

void OnCPUStackCollector::setScale(uint64_t freq)
{
    this->freq = freq;
    scales->Period = 1e9 / freq;
}

uint64_t *OnCPUStackCollector::count_values(void *data)
{
    return new uint64_t[scale_num]{
        *(uint32_t *)data,
    };
};

int OnCPUStackCollector::ready(void)
{
    EBPF_LOAD_OPEN_INIT();
    bool *online_mask;
    int num_online_cpus;
    err = parse_cpu_mask_file("/sys/devices/system/cpu/online", &online_mask, &num_online_cpus);
    CHECK_ERR_RN1(err, "Fail to get online CPU numbers");

    num_cpus = libbpf_num_possible_cpus();
    CHECK_ERR_RN1(num_cpus <= 0, "Fail to get the number of processors");

    struct perf_event_attr attr = {
        .type = PERF_TYPE_HARDWARE,
        .size = sizeof(attr),
        .config = PERF_COUNT_HW_CPU_CYCLES,
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
        int pefd = perf_event_open(&attr, tgid ? tgid : -1, cpu, -1, 0);
        if (pefd < 0)
        {
            if (attr.type != PERF_TYPE_SOFTWARE)
            {
                HINT_ERR("Hardware perf events not exist, try to attach to software event");
                attr.type = PERF_TYPE_SOFTWARE;
                attr.config = PERF_COUNT_SW_CPU_CLOCK;
                pefd = perf_event_open(&attr, tgid ? tgid : -1, cpu, -1, 0);
                CHECK_ERR_RN1(pefd < 0, "Fail to set up performance monitor on a CPU/Core");
            }
            else
                DEAL_ERR(return -1, "Fail to set up performance monitor on a CPU/Core");
        }
        pefds[cpu] = pefd;
        /* Attach a BPF program on a CPU */
        links[cpu] = bpf_program__attach_perf_event(skel->progs.do_stack, pefd); // 与内核bpf程序联系
        CHECK_ERR_RN1(!links[cpu], "Fail to attach bpf program");
    }
    return 0;
}

void OnCPUStackCollector::finish(void)
{
    for (int i = 0; i < num_cpus; i++)
    {
        bpf_link__destroy(links[i]);
        close(pefds[i]);
    }
    free(links);
    free(pefds);
    links = NULL;
    pefds = NULL;
    UNLOAD_PROTO;
}

void OnCPUStackCollector::activate(bool tf)
{
    ACTIVE_SET(tf);
}

const char *OnCPUStackCollector::getName(void)
{
    return "OnCPUStackCollector";
}