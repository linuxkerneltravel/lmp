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
// author: GaoYixiang
//
// probe ebpf 程序的包装类，实现接口和一些自定义方法

#include "bpf/probe.h"
#include "uprobe_helpers.h"

double StackCountStackCollector::count_value(void *data)
{
    return *(uint32_t *)data;
}

StackCountStackCollector::StackCountStackCollector()
{
    scale = {
        .Type = "StackCounts",
        .Unit = "Counts",
        .Period = 1,
    };
};

void splitString(std::string symbol, const char split, std::vector<std::string> &res)
{
    if (symbol == "")
        return;
    std::string strs = symbol + split;
    size_t pos = strs.find(split);
    while (pos != strs.npos)
    {
        std::string temp = strs.substr(0, pos);
        res.push_back(temp);
        strs = strs.substr(pos + 1, strs.size());
        pos = strs.find(split);
    }
}
void StackCountStackCollector::setScale(std::string probe)
{
    this->probe = probe;
    auto type = new std::string(probe+scale.Type);
    scale.Type = type->c_str();
};

int StackCountStackCollector::load(void)
{
    StackProgLoadOpen(skel->bss->apid = pid;);
    return 0;
};

int StackCountStackCollector::attach(void)
{
    std::vector<std::string> strList;
    splitString(probe, ':', strList);

    if (strList.size() == 1 || (strList.size() == 3 && strList[0] == "p" && strList[1] == ""))
    {
        // probe a kernel function
        std::string func = probe;
        if (strList.size() == 3 && strList[0] == "p" && strList[1] == "")
            func = strList[2];
        skel->links.handle =
            bpf_program__attach_kprobe(skel->progs.handle, false, func.c_str());
        CHECK_ERR(!skel->links.handle, "Fail to attach kprobe");
        return 0;
    }
    else if (strList.size() == 3 && strList[0] == "t")
    {
        // probe a kernel tracepoint
        skel->links.handle_tp =
            bpf_program__attach_tracepoint(skel->progs.handle_tp, strList[1].c_str(), strList[2].c_str());
        CHECK_ERR(!skel->links.handle_tp, "Fail to attach tracepoint");
        return 0;
    }
    else if (strList.size() == 2 || (strList.size() == 3 && strList[0] == "p" && strList[1] != ""))
    {
        // probe a user-space function in the library 'lib'
        char *binary, *function;
        char bin_path[128];
        std::string func = probe;
        off_t func_off;
        if (strList.size() == 3)
            func = strList[1] + ":" + strList[2];

        binary = strdup(func.c_str());
        function = strchr(binary, ':'); // 查找：首次出现的位置
        *function = '\0';
        function++;

        if (resolve_binary_path(binary, pid, bin_path, sizeof(bin_path)))
            free(binary);

        func_off = get_elf_func_offset(bin_path, function);
        if (func_off < 0)
            free(binary);
        skel->links.handle =
            bpf_program__attach_uprobe(skel->progs.handle, false, pid,
                                       bin_path, func_off);
        CHECK_ERR(!skel->links.handle, "Fail to attach uprobe");
        return 0;
    }
    else if (strList.size() == 3 && strList[0] == "u")
    {
        // probe a USDT tracepoint
        return 0;
    }
    else
    {
        printf("Type must be 'p', 't', or 'u' or too any args");
    }

    scale.Type = (probe + scale.Type).c_str();
    return 0;
};

void StackCountStackCollector::detach(void)
{
    defaultDetach;
};

void StackCountStackCollector::unload(void)
{
    defaultUnload;
};
