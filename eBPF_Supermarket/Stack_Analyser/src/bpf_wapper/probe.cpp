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

#include "bpf_wapper/probe.h"
#include "trace_helpers.h"
#include "uprobe_helpers.h"

// ========== implement virtual func ==========

uint64_t *ProbeStackCollector::count_values(void *data)
{
    time_tuple *p = (time_tuple *)data;
    return new uint64_t[scale_num]{
        p->lat,
        p->count,
    };
};

void ProbeStackCollector::setScale(std::string probe)
{
    this->probe = probe;
    for (int i = 0; i < scale_num; i++)
        scales[i].Type = probe + scales[i].Type;
};

int ProbeStackCollector::load(void)
{
    EBPF_LOAD_OPEN_INIT();
    return 0;
};

void splitStr(std::string symbol, const char split, std::vector<std::string> &res)
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

static int get_binpath(char *path, int pid)
{
    char mode[16], line[128], buf[64];
    size_t seg_start, seg_end, seg_off;
    FILE *f;
    int i = 0;

    sprintf(buf, "/proc/%d/maps", pid);
    f = fopen(buf, "r");
    if (!f)
        return -1;

    while (fscanf(f, "%zx-%zx %s %zx %*s %*d%[^\n]\n",
                  &seg_start, &seg_end, mode, &seg_off, line) == 5)
    {
        i = 0;
        while (isblank(line[i]))
            i++;
        if (strstr(line + i, "libc.so.6"))
        {
            break;
        }
    }

    strcpy(path, line + i);
    fclose(f);
    return 0;
}
static int attach_kprobes(struct probe_bpf *skel, std::string func)
{
    skel->links.dummy_kprobe =
        bpf_program__attach_kprobe(skel->progs.dummy_kprobe, false, func.c_str());
    CHECK_ERR_RN1(!skel->links.dummy_kprobe, "Fail to attach kprobe");
    skel->links.dummy_kretprobe =
        bpf_program__attach_kprobe(skel->progs.dummy_kretprobe, true, func.c_str());
    CHECK_ERR_RN1(!skel->links.dummy_kretprobe, "Fail to attach ketprobe");
    return 0;
}
static int attach_uprobes(struct probe_bpf *skel, std::string probe, int pid)
{
    char *binary, *function;
    char bin_path[128];
    std::string func = probe;
    off_t func_off;

    binary = strdup(func.c_str());
    function = strchr(binary, ':'); // 查找：首次出现的位置
    *function = '\0';
    function++;

    if (resolve_binary_path(binary, pid, bin_path, sizeof(bin_path)))
        free(binary);

    func_off = get_elf_func_offset(bin_path, function);
    if (func_off < 0)
        free(binary);
    skel->links.dummy_kprobe =
        bpf_program__attach_uprobe(skel->progs.dummy_kprobe, false, pid,
                                   bin_path, func_off);
    CHECK_ERR_RN1(!skel->links.dummy_kprobe, "Fail to attach uprobe");
    skel->links.dummy_kretprobe =
        bpf_program__attach_uprobe(skel->progs.dummy_kretprobe, true, pid,
                                   bin_path, func_off);
    CHECK_ERR_RN1(!skel->links.dummy_kretprobe, "Fail to attach uprobe");
    return 0;
}

static int attach_tp(struct probe_bpf *skel, std::string tp_class, std::string func)
{

    skel->links.tp_exit =
        bpf_program__attach_tracepoint(skel->progs.tp_exit, tp_class.c_str(), func.c_str());
    CHECK_ERR_RN1(!skel->links.tp_exit, "Fail to attach tracepoint");
    return 0;
}

static int attach_usdt(struct probe_bpf *skel, std::string func, int pid)
{
    char bin_path[128];
    int err = get_binpath(bin_path, pid);
    CHECK_ERR_RN1(err, "Fail to get lib path");
    skel->links.usdt_exit =
        bpf_program__attach_usdt(skel->progs.usdt_exit, pid, bin_path, "libc", func.c_str(), NULL);
    CHECK_ERR_RN1(!skel->links.usdt_exit, "Fail to attach usdt");
    return 0;
}

int ProbeStackCollector::attach(void)
{
    // dynamic mounting
    std::vector<std::string> strList;
    splitStr(probe, ':', strList);
    std::string func = probe;
    int err = 0;

    if (strList.size() == 3 && strList[0] == "p" && strList[1] == "")
        func = strList[2];
    if (strList.size() == 1 || (strList.size() == 3 && strList[0] == "p" && strList[1] == ""))
    {
        err = attach_kprobes(skel, func);
    }
    else if (strList.size() == 3 && strList[0] == "t")
    {
        err = attach_tp(skel, strList[1], strList[2]);
    }
    else if (strList.size() == 2 || (strList.size() == 3 && strList[0] == "p" && strList[1] != ""))
    {
        if (strList.size() == 3)
            func = strList[1] + ":" + strList[2];
        err = attach_uprobes(skel, func, tgid);
    }
    else if (strList.size() == 3 && strList[0] == "u")
    {
        err = attach_usdt(skel, strList[2], tgid);
    }
    else
    {
        printf("Type must be 'p', 't', or 'u' or too any args");
    }

    CHECK_ERR_RN1(err, "Fail to attach");

    return 0;
};

void ProbeStackCollector::detach(void)
{
    DETACH_PROTO;
};

void ProbeStackCollector::unload(void)
{
    UNLOAD_PROTO;
};

void ProbeStackCollector::activate(bool tf)
{
    ACTIVE_SET(tf);
}

const char *ProbeStackCollector::getName(void)
{
    return "ProbeStackCollector";
}

// ========== other implementations ==========

ProbeStackCollector::ProbeStackCollector()
{
    scale_num = 2;
    scales = new Scale[scale_num]{
        {"Time", 1, "nanoseconds"},
        {"Count", 1, "counts"},
    };
};