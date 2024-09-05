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
// on cpu ebpf程序的包装类，声明接口和一些自定义方法

#ifndef _SA_ON_CPU_H__
#define _SA_ON_CPU_H__

#include "bpf_wapper/eBPFStackCollector.h"
#include "on_cpu.skel.h"

#ifdef __cplusplus
class OnCPUStackCollector : public StackCollector
{
private:
	struct on_cpu_bpf *skel = __null;

	int *pefds = NULL;
	int num_cpus = 0;
	struct bpf_link **links = NULL;

protected:
	virtual uint64_t *count_values(void *);

public:
	void setScale(uint64_t freq);
	OnCPUStackCollector();
    virtual int ready(void);
    virtual void finish(void);
	virtual void activate(bool tf);
    virtual const char *getName(void);
};
#endif

#endif