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
// 主函数，负责参数解析，管理被监控命令对应的进程，数据输出

#include <signal.h>
#include <iostream>

#include "bpf/on_cpu.h"
#include "bpf/off_cpu.h"
#include "bpf/mem.h"
#include "bpf/io.h"
#include "bpf/readahead.h"
#include "bpf/probe.h"
#include "bpf/biostack.h"

#include "sa_user.h"
#include "clipp.h"


namespace MainConfig
{
    int run_time = __INT_MAX__; // 运行时间
    unsigned delay = 5;         // 设置输出间隔
    std::string command = "";
    int32_t target_pid = -1;
}

std::vector<StackCollector *> StackCollectorList;

void endCollect(void)
{
    signal(SIGINT, SIG_IGN);
    for (auto Item : StackCollectorList)
    {
        if (MainConfig::run_time > 0)
        {
            std::cout << std::string(*Item) << std::endl;
        }
        Item->detach();
        Item->unload();
    }
    if (MainConfig::command.length())
    {
        kill(MainConfig::target_pid, SIGTERM);
    }
}

uint64_t IntTmp;
std::string StrTmp;

int main(int argc, char *argv[])
{
    auto MainOption = ((
                           ((clipp::option("-p", "--pid") & clipp::value("pid of sampled process, default -1 for all", MainConfig::target_pid)) % "set pid of process to monitor") |
                           ((clipp::option("-c", "--command") & clipp::value("to be sampled command to run, default none", MainConfig::command)) % "set command for monitoring the whole life")),
                       (clipp::option("-d", "--delay") & clipp::value("delay time(seconds) to output, default 5", MainConfig::delay)) % "set the interval to output",
                       (clipp::option("-t", "--timeout") & clipp::value("run time, default nearly infinite", MainConfig::run_time)) % "set the total simpling time");

    auto SubOption = (clipp::option("-U", "--user-stack-only").call([]
                                                                    { StackCollectorList.back()->kstack = false; }) %
                          "only sample user stacks",
                      clipp::option("-K", "--kernel-stack-only").call([]
                                                                      { StackCollectorList.back()->ustack = false; }) %
                          "only sample kernel stacks",
                      (clipp::option("-m", "--max-value") & clipp::value("max threshold of sampled value", IntTmp).call([]
                                                                                                                        { StackCollectorList.back()->max = IntTmp; })) %
                          "set the max threshold of sampled value",
                      (clipp::option("-n", "--min-value") & clipp::value("min threshold of sampled value", IntTmp).call([]
                                                                                                                        { StackCollectorList.back()->min = IntTmp; })) %
                          "set the min threshold of sampled value");

    auto OnCpuOption = (clipp::option("on_cpu").call([]
                                                     { StackCollectorList.push_back(new OnCPUStackCollector()); }) %
                        "sample the call stacks of on-cpu processes") &
                       (clipp::option("-F", "--frequency") & clipp::value("sampling frequency", IntTmp).call([]
                                                                                                             { static_cast<OnCPUStackCollector *>(StackCollectorList.back())->setScale(IntTmp); }) %
                                                                 "sampling at a set frequency",
                        SubOption);

    auto OffCpuOption = clipp::option("off_cpu").call([]
                                                      { StackCollectorList.push_back(new OffCPUStackCollector()); }) %
                            "sample the call stacks of off-cpu processes" &
                        SubOption;

    auto MemoryOption = clipp::option("mem").call([]
                                                  { StackCollectorList.push_back(new MemoryStackCollector()); }) %
                            "sample the memory usage of call stacks" &
                        SubOption;

    auto IOOption = clipp::option("io").call([]
                                             { StackCollectorList.push_back(new IOStackCollector()); }) %
                        "sample the IO data volume of call stacks" &
                    ((clipp::option("--mod") & (clipp::option("count").call([]
                                                                            { static_cast<IOStackCollector *>(StackCollectorList.back())->setScale(IOStackCollector::io_mod::COUNT); }) %
                                                    "Counting the number of I/O operations" |
                                                clipp::option("ave").call([]
                                                                          { static_cast<IOStackCollector *>(StackCollectorList.back())->setScale(IOStackCollector::io_mod::AVE); }) %
                                                    "Counting the ave of I/O operations" |
                                                clipp::option("size").call([]
                                                                           { static_cast<IOStackCollector *>(StackCollectorList.back())->setScale(IOStackCollector::io_mod::SIZE); }) %
                                                    "Counting the size of I/O operations")) %
                         "set the statistic mod",
                     SubOption);

    auto ReadaheadOption = clipp::option("readahead").call([]
                                                    { StackCollectorList.push_back(new ReadaheadStackCollector()); }) %
                               "sample the readahead hit rate of call stacks" &
                           SubOption;
    auto StackCountOption = clipp::option("probe").call([]
                                                             { StackCollectorList.push_back(new StackCountStackCollector()); }) %
                                "sample the counts of calling stacks" &
                            (clipp::option("-S", "--String") & clipp::value("probe String", StrTmp).call([]
                                                                                                         { static_cast<StackCountStackCollector *>(StackCollectorList.back())->setScale(StrTmp); }) %
                                                                   "sampling at a set probe string",
                             SubOption);
    auto BioStackOption = clipp::option("bio").call([]
                                                  { StackCollectorList.push_back(new BioStackStackCollector()); }) %
                            "sample the bio of calling stacks" &
                        SubOption;

    auto cli = (MainOption,
                clipp::option("-v", "--version").call([]
                                                      { std::cout << "verion 2.0\n\n"; }) %
                    "show version",
                OnCpuOption,
                OffCpuOption,
                MemoryOption,
                IOOption,
                ReadaheadOption,
                StackCountOption,
                BioStackOption) %
               "statistic call trace relate with some metrics";

    if (!clipp::parse(argc, argv, cli))
    {
        std::cout << clipp::make_man_page(cli, argv[0]) << '\n';
        return 0;
    }

    uint64_t eventbuff = 1;
    int child_exec_event_fd = eventfd(0, EFD_CLOEXEC);
    CHECK_ERR(child_exec_event_fd < 0, "failed to create event fd");
    if (MainConfig::command.length())
    {
        MainConfig::target_pid = fork();
        switch (MainConfig::target_pid)
        {
        case -1:
        {
            std::cout << "command create failed." << std::endl;
            return -1;
        }
        case 0:
        {
            const auto bytes = read(child_exec_event_fd, &eventbuff, sizeof(eventbuff));
            CHECK_ERR(bytes < 0, "failed to read from fd %ld", bytes)
            else CHECK_ERR(bytes != sizeof(eventbuff), "read unexpected size %ld", bytes);
            printf("child exec %s\n", MainConfig::command.c_str());
            CHECK_ERR_EXIT(execl("/bin/bash", "bash", "-c", MainConfig::command.c_str(), NULL), "failed to execute child command");
            break;
        }
        default:
        {
            printf("create child %d\n", MainConfig::target_pid);
            break;
        }
        }
    }

    for (auto Item = StackCollectorList.begin(); Item != StackCollectorList.end();)
    {
        (*Item)->pid = MainConfig::target_pid;
        if ((*Item)->load())
        {
            goto err;
        }
        if ((*Item)->attach())
        {
            goto err;
        }
        Item++;
        continue;
    err:
        fprintf(stderr, "%s eBPF prog err\n", (*Item)->scale.Type);
        (*Item)->detach();
        (*Item)->unload();
        Item = StackCollectorList.erase(Item);
    }

    if (MainConfig::command.length())
    {
        printf("wake up child\n");
        write(child_exec_event_fd, &eventbuff, sizeof(eventbuff));
    }

    // printf("display mode: %d\n", MainConfig::d_mode);

    for (; MainConfig::run_time > 0 && (MainConfig::target_pid < 0 || !kill(MainConfig::target_pid, 0)); MainConfig::run_time -= MainConfig::delay)
    {
        sleep(MainConfig::delay);
        for (auto Item : StackCollectorList)
        {
            Item->detach();
            std::cout << std::string(*Item);
            Item->attach();
        }
    }

    atexit(endCollect);
}