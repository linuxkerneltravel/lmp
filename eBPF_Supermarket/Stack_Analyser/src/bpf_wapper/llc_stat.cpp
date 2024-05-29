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
// ebpf程序包装类的模板，实现接口和一些自定义方法

#include "bpf_wapper/llc_stat.h"
#include <sys/syscall.h>
#include <linux/perf_event.h>

extern "C"
{
	extern int parse_cpu_mask_file(const char *fcpu, bool **mask, int *mask_sz);
}

// ========== implement virtual func ==========

uint64_t *LlcStatStackCollector::count_values(void *data)
{
	auto p = (llc_stat *)data;
	return new uint64_t[scale_num]{
		p->miss,
		p->ref,
		p->ref * 100 / (p->miss + p->ref),
	};
};

int LlcStatStackCollector::ready(void)
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
		.sample_period = scales->Period,
		.inherit = 1,
		.freq = 1, // use freq instead of period
	};
	mpefds = (int *)malloc(num_cpus * sizeof(int));
	rpefds = (int *)malloc(num_cpus * sizeof(int));
	for (int i = 0; i < num_cpus; i++)
	{
		mpefds[i] = rpefds[i] = -1;
	}
	mlinks = (struct bpf_link **)calloc(num_cpus, sizeof(struct bpf_link *));
	rlinks = (struct bpf_link **)calloc(num_cpus, sizeof(struct bpf_link *));
	for (int cpu = 0; cpu < num_cpus; cpu++)
	{
		/* skip offline/not present CPUs */
		if (cpu >= num_online_cpus || !online_mask[cpu])
		{
			continue;
		}
		/* Set up performance monitoring on a CPU/Core */
		attr.config = PERF_COUNT_HW_CACHE_MISSES;
		int pefd = syscall(SYS_perf_event_open, &attr, tgid ? tgid : -1, cpu, -1, 0);
		CHECK_ERR_RN1(pefd < 0, "Fail to set up performance monitor on a CPU/Core");
		mpefds[cpu] = pefd;
		/* Attach a BPF program on a CPU */
		mlinks[cpu] = bpf_program__attach_perf_event(skel->progs.on_cache_miss, pefd);
		CHECK_ERR_RN1(!mlinks[cpu], "Fail to attach bpf program");

		attr.config = PERF_COUNT_HW_CACHE_REFERENCES;
		pefd = syscall(SYS_perf_event_open, &attr, tgid ? tgid : -1, cpu, -1, 0);
		CHECK_ERR_RN1(pefd < 0, "Fail to set up performance monitor on a CPU/Core");
		rpefds[cpu] = pefd;
		/* Attach a BPF program on a CPU */
		rlinks[cpu] = bpf_program__attach_perf_event(skel->progs.on_cache_ref, pefd);
		CHECK_ERR_RN1(!rlinks[cpu], "Fail to attach bpf program");
	}
    return 0;
}

void LlcStatStackCollector::finish(void)
{
	for (int cpu = 0; cpu < num_cpus; cpu++)
	{
		bpf_link__destroy(mlinks[cpu]);
		bpf_link__destroy(rlinks[cpu]);
		close(mpefds[cpu]);
		close(rpefds[cpu]);
	}
	free(mlinks);
	free(rlinks);
	free(mpefds);
	free(rpefds);
	mlinks = rlinks = NULL;
	mpefds = rpefds = NULL;
	UNLOAD_PROTO;
}

void LlcStatStackCollector::activate(bool tf)
{
	ACTIVE_SET(tf);
}

const char *LlcStatStackCollector::getName(void)
{
	return "LlcStatStackCollector";
}

// ========== other implementations ==========

LlcStatStackCollector::LlcStatStackCollector()
{
	const int DefaultPeriod = 100;
	scale_num = 3;
	scales = new Scale[3]{
		{"CacheMissingCount", DefaultPeriod, "counts"},
		{"CacheReferenceCount", DefaultPeriod, "counts"},
		{"CacheHitPercentage", 1, "percent"},
	};
};

void LlcStatStackCollector::setScale(uint64_t p)
{
	scales[0].Period = scales[1].Period = p;
}