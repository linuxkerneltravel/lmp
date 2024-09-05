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

uint64_t *IOStackCollector::count_values(void *data)
{
    io_tuple *p = (io_tuple *)data;
    return new uint64_t[scale_num]{
        p->size,
        p->count,
    };
};

IOStackCollector::IOStackCollector()
{
    scale_num = 2;
    scales = new Scale[scale_num]{
        {"IOSize", 1, "bytes"},
        {"IOCount", 1, "counts"},
    };
};

int IOStackCollector::ready(void)
{
    EBPF_LOAD_OPEN_INIT();
    ATTACH_PROTO;
    return 0;
}

void IOStackCollector::finish(void)
{
    DETACH_PROTO;
    UNLOAD_PROTO;
}

void IOStackCollector::activate(bool tf)
{
    ACTIVE_SET(tf);
}

const char *IOStackCollector::getName(void)
{
    return "IOStackCollector";
}