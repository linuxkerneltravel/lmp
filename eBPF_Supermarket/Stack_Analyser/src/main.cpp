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

#include "bpf_wapper/on_cpu.h"
#include "bpf_wapper/off_cpu.h"
#include "bpf_wapper/memleak.h"
#include "bpf_wapper/io.h"
#include "bpf_wapper/readahead.h"
#include "bpf_wapper/probe.h"
#include "bpf_wapper/bio.h"

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
clipp::man_page *man_page;

int main(int argc, char *argv[])
{
    man_page = new clipp::man_page();
    clipp::group cli;
    {
        auto SubOption = (clipp::option("-u")
                                  .call([]
                                        { StackCollectorList.back()->kstack = false; }) %
                              "Only sample user stacks",
                          clipp::option("-k")
                                  .call([]
                                        { StackCollectorList.back()->ustack = false; }) %
                              "Only sample kernel stacks",
                          (clipp::option("-m") &
                           clipp::value("max", IntTmp)
                               .call([]
                                     { StackCollectorList.back()->max = IntTmp; })) %
                              "Set the max threshold of sampled value",
                          (clipp::option("-n") &
                           clipp::value("min", IntTmp)
                               .call([]
                                     { StackCollectorList.back()->min = IntTmp; })) %
                              "Set the min threshold of sampled value\n");

        auto OnCpuOption = (clipp::option("on_cpu")
                                .call([]
                                      { StackCollectorList.push_back(new OnCPUStackCollector()); }) %
                            COLLECTOR_INFO("on-cpu")) &
                           ((clipp::option("-f") &
                             clipp::value("freq", IntTmp)
                                 .call([]
                                       { static_cast<OnCPUStackCollector *>(StackCollectorList.back())
                                             ->setScale(IntTmp); })) %
                                "Set sampling frequency",
                            SubOption);

        auto OffCpuOption = clipp::option("off_cpu")
                                    .call([]
                                          { StackCollectorList.push_back(new OffCPUStackCollector()); }) %
                                COLLECTOR_INFO("off-cpu") &
                            (SubOption);

        auto MemleakOption = (clipp::option("memleak")
                                  .call([]
                                        { StackCollectorList.push_back(new MemleakStackCollector()); }) %
                              COLLECTOR_INFO("memleak")) &
                             ((clipp::option("-i") &
                               clipp::value("interval", IntTmp)
                                   .call([]
                                         { static_cast<MemleakStackCollector *>(StackCollectorList.back())
                                               ->sample_rate = IntTmp; })) %
                                  "Set the sampling interval",
                              clipp::option("-w")
                                      .call([]
                                            { static_cast<MemleakStackCollector *>(StackCollectorList.back())
                                                  ->wa_missing_free = true; }) %
                                  "Workaround to alleviate misjudgments when free is missing",
                              SubOption);

        auto IOOption = clipp::option("io")
                                .call([]
                                      { StackCollectorList.push_back(new IOStackCollector()); }) %
                            COLLECTOR_INFO("io") &
                        ((clipp::option("-M") &
                          (clipp::option("count")
                               .call([]
                                     { static_cast<IOStackCollector *>(StackCollectorList.back())
                                           ->setScale(IOStackCollector::io_mod::COUNT); }) |
                           clipp::option("aver")
                               .call([]
                                     { static_cast<IOStackCollector *>(StackCollectorList.back())
                                           ->setScale(IOStackCollector::io_mod::AVE); }) |
                           clipp::option("size")
                               .call([]
                                     { static_cast<IOStackCollector *>(StackCollectorList.back())
                                           ->setScale(IOStackCollector::io_mod::SIZE); }))) %
                             "Set the statistic mod",
                         SubOption);

        auto ReadaheadOption = clipp::option("readahead")
                                       .call([]
                                             { StackCollectorList.push_back(new ReadaheadStackCollector()); }) %
                                   COLLECTOR_INFO("readahead") &
                               (SubOption);

        auto StackCountOption = clipp::option("probe")
                                        .call([]
                                              { StackCollectorList.push_back(new StackCountStackCollector()); }) %
                                    COLLECTOR_INFO("probe") &
                                ((clipp::option("-b") &
                                  clipp::value("probe", StrTmp)
                                      .call([]
                                            { static_cast<StackCountStackCollector *>(StackCollectorList.back())
                                                  ->setScale(StrTmp); })) %
                                     "Sampling at a set probe string",
                                 SubOption);

        auto MainOption = _GREEN "Some overall options" _RE %
                          ((
                               ((clipp::option("-p") &
                                 clipp::value("pid", MainConfig::target_pid)) %
                                "Set the pid of the process to be tracked; default is -1, which keeps track of all processes") |
                               ((clipp::option("-c") &
                                 clipp::value("command", MainConfig::command)) %
                                "Set the command to be run and sampled; defaults is none")),
                           (clipp::option("-d") &
                            clipp::value("interval", MainConfig::delay)) %
                               "Set the output delay time (seconds); default is 5",
                           (clipp::option("-t") &
                            clipp::value("duration", MainConfig::run_time)) %
                               "Set the total sampling time; default is __INT_MAX__");
        auto BioStackOption = clipp::option("bio")
                                      .call([]
                                            { StackCollectorList.push_back(new BioStackCollector()); }) %
                                  "sample the bio of calling stacks" &
                              SubOption;
        auto Info = _GREEN "Information of the application" _RE %
                    ((clipp::option("-v", "--version")
                          .call([]
                                { std::cout << "verion 2.0\n\n"; }) %
                      "Show version"),
                     (clipp::option("-h", "--help")
                          .call([]
                                { std::cout << *man_page << std::endl; exit(0); }) %
                      "Show man page"));

        cli = (OnCpuOption,
               OffCpuOption,
               MemleakOption,
               IOOption,
               ReadaheadOption,
               StackCountOption,
               BioStackOption,
               MainOption,
               Info);
    }
    {
        auto fmt = clipp::doc_formatting{}
                       .first_column(3)
                       .doc_column(25)
                       .last_column(128);
        *man_page = clipp::make_man_page(cli, argv[0], fmt)
                        .prepend_section("DESCRIPTION", _RED "Count the function call stack associated with some metric.\n" _RE BANNER)
                        .append_section("LICENSE", _RED "Apache Licence 2.0" _RE);
    }
    if (!clipp::parse(argc, argv, cli))
    {
        std::cerr << *man_page << std::endl;
        return -1;
    }
    if (StackCollectorList.size() == 0)
    {
        printf(_ERED "At least one collector needs to be added.\n" _RE);
        return -1;
    }

    printf(BANNER "\n");

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
            CHECK_ERR(true, "Command create failed.");
        }
        case 0:
        {
            const auto bytes = read(child_exec_event_fd, &eventbuff, sizeof(eventbuff));
            CHECK_ERR(bytes < 0, "Failed to read from fd %ld", bytes)
            else CHECK_ERR(bytes != sizeof(eventbuff), "Read unexpected size %ld", bytes);
            printf("child exec %s\n", MainConfig::command.c_str());
            CHECK_ERR_EXIT(execl("/bin/bash", "bash", "-c", MainConfig::command.c_str(), NULL), "failed to execute child command");
            break;
        }
        default:
        {
            printf("Create child %d\n", MainConfig::target_pid);
            break;
        }
        }
    }

    for (auto Item = StackCollectorList.begin(); Item != StackCollectorList.end();)
    {
        printf(_RED "Attach %dth collecotor %s.\n" _RE, (int)(Item - StackCollectorList.begin()) + 1, (*Item)->scale.Type);
        (*Item)->pid = MainConfig::target_pid;
        if ((*Item)->load() || (*Item)->attach())
            goto err;
        Item++;
        continue;
    err:
        fprintf(stderr, _ERED "Collector %s err.\n" _RE, (*Item)->scale.Type);
        (*Item)->detach();
        (*Item)->unload();
        Item = StackCollectorList.erase(Item);
    }

    if (StackCollectorList.size() == 0)
    {
        fprintf(stderr, _ERED "No collecter to run.\n" _RE);
        return -1;
    }

    if (MainConfig::command.length())
    {
        printf(_GREEN "Wake up child.\n" _RE);
        write(child_exec_event_fd, &eventbuff, sizeof(eventbuff));
    }

    atexit(endCollect);

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
}