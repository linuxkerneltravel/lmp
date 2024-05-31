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
// readahead ebpf程序的包装类，实现接口和一些自定义方法

#include "bpf_wapper/readahead.h"

uint64_t *ReadaheadStackCollector::count_values(void *data)
{
    ra_tuple *p = (ra_tuple *)data;
    return new uint64_t[scale_num]{
        p->expect - p->truth,
        p->truth,
    };
};

ReadaheadStackCollector::ReadaheadStackCollector()
{
    showDelta = false;
    scale_num = 2;
    scales = new Scale[scale_num]{
        {"UnusedReadaheadPages", 1, "pages"},
        {"UsedReadaheadPages", 1, "pages"},
    };
};

int ReadaheadStackCollector::ready(void)
{
    EBPF_LOAD_OPEN_INIT();
    ATTACH_PROTO;
    return 0;
}

void ReadaheadStackCollector::finish(void)
{
    DETACH_PROTO;
    UNLOAD_PROTO;
}

void ReadaheadStackCollector::activate(bool tf)
{
    ACTIVE_SET(tf);
}

const char *ReadaheadStackCollector::getName(void)
{
    return "ReadaheadStackCollector";
}