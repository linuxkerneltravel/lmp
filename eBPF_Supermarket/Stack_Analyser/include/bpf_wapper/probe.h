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
// probe ebpf程序的包装类，声明接口和一些自定义方法

#include "bpf_wapper/eBPFStackCollector.h"
#include "probe.skel.h"

class ProbeStackCollector : public StackCollector
{
private:
    struct probe_bpf *skel = __null;

public:
    std::string probe;

protected:
    virtual uint64_t *count_values(void *);

public:
    void setScale(std::string probe);
    ProbeStackCollector();
    virtual int load(void);
    virtual int attach(void);
    virtual void detach(void);
    virtual void unload(void);
    virtual void activate(bool tf);
};
