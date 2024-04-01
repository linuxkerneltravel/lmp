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
// io ebpf程序的包装类，声明接口和一些自定义方法

#ifndef _SA_IO_H__
#define _SA_IO_H__

#include <asm/types.h>
typedef struct
{
    __u64 size;
    __u64 count;
} io_tuple;

#ifdef __cplusplus
#include "io.skel.h"
#include "bpf_wapper/eBPFStackCollector.h"

class IOStackCollector : public StackCollector
{
private:
    declareEBPF(io);

public:
    enum io_mod
    {
        COUNT,
        SIZE,
        AVE,
    } DataType = COUNT;

protected:
    virtual double count_value(void *);

public:
    void setScale(io_mod mod);
    IOStackCollector();
    virtual int load(void);
    virtual int attach(void);
    virtual void detach(void);
    virtual void unload(void);
	virtual void activate(bool tf);
};
#endif

#endif