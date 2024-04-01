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
// io ebpf程序的包装类，实现接口和一些自定义方法

#include "bpf_wapper/io.h"

double IOStackCollector::count_value(void *data)
{
    io_tuple *p = (io_tuple *)data;
    switch (DataType)
    {
    case AVE:
        return 1. * p->size / p->count;
    case SIZE:
        return p->size;
    case COUNT:
        return p->count;
    default:
        return 0;
    }
};

void IOStackCollector::setScale(io_mod mod)
{
    DataType = mod;
    static const char *Types[] = {"IOCount", "IOSize", "AverageIOSize"};
    static const char *Units[] = {"counts", "bytes", "bytes"};
    scale.Type = Types[mod];
    scale.Unit = Units[mod];
    scale.Period = 1;
};

IOStackCollector::IOStackCollector()
{
    ustack = true;
    kstack = false;
    setScale(DataType);
};

int IOStackCollector::load(void)
{
    StackProgLoadOpen(skel->rodata->target_pid = pid;);
    return 0;
}

int IOStackCollector::attach(void)
{
    defaultAttach;
    return 0;
}

void IOStackCollector::detach(void)
{
    defaultDetach;
}

void IOStackCollector::unload(void)
{
    defaultUnload;
}

void IOStackCollector::activate(bool tf){
    defaultActivateBy(tf);
}