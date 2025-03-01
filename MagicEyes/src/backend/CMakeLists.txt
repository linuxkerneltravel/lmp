# \copyright
# Copyright (c) 2024 by the lmp/magic_eyes project authors. All Rights Reserved.
#
# This file is open source software, licensed to you under the terms
# of the Apache License, Version 2.0 (the "License").  See the NOTICE file
# distributed with this work for additional information regarding copyright
# ownership.  You may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
# -----------------------------------------------------------------------------------------
# \brief
#      backend 顶层 CMakeLists 文件
#      控制哪些工具编译，哪些不编译
# \usage
#      编译所有工具
#           cmake -DBUILD_ALL=ON ..
#      编译单独某个工具，如 fs_watcher
#           cmake -DBUILD_FS_WATCHER=ON ..
# -----------------------------------------------------------------------------------------
include_directories(fs hypervisor memory net process system_diagnosis)
# Tips: cmake的 option选项会存储在 <build_dir>/CMakeCache.txt中，若需要修改配置，请先删除CMakeCache.txt
#       再运行 cmake -DXXX= ON .. 更新新的配置选项
option(BUILD_ALL "is build all tools? "                     OFF)
# fs部分
option(BUILD_FS_WATCHER "is build fs_watcher? "             OFF)
# memory部分
option(BUILD_MEM_WATCHER "is build mem_watcher? "           OFF)
# net部分
option(BUILD_NET_WATCHER "is build net_watcher? "           OFF)
option(BUILD_DELAY_ANALYSIS "is build delay_analysis? "     OFF)
# process部分
option(BUILD_CPU_WATCHER "is build cpu_watcher? "           OFF)
option(BUILD_PROC_IMAGE "is build proc_image? "             OFF)
# hypervisor部分
option(BUILD_KVM_WATCHER "is build kvm_watcher? "           OFF)
# system_diagnosis
option(BUILD_STACK_ANALYZER "is build stack_analyzer? "     OFF)
# IPC
option(BUILD_IPC_WATCHER "is build ipc_watcher? "     OFF)

if (BUILD_ALL)
    message(STATUS "build all tools")
    # TODO(fzy, 2024.03.13) 没找到代码
    # add_subdirectory(fs/fs_watcher)
    add_subdirectory(memory/mem_watcher)
    add_subdirectory(net/net_watcher)
    add_subdirectory(net/delay_analysis)
    add_subdirectory(process/cpu_watcher)
    add_subdirectory(process/proc_image)
    # TODO(fzy, 2024.03.13) 没有kvm的环境
    add_subdirectory(hypervisor/kvm_watcher)
    add_subdirectory(system_diagnosis/stack_analyzer)
    add_subdirectory(ipc/ipc_watcher)
else ()
    message(STATUS "----------------------------------------")
    message(STATUS "build fs_watcher? ${BUILD_FS_WATCHER}")
    if (BUILD_FS_WATCHER)
        add_subdirectory(fs/fs_watcher)
    endif ()

    message(STATUS "build mem_watcher? ${BUILD_MEM_WATCHER}")
    if (BUILD_MEM_WATCHER)
        add_subdirectory(memory/mem_watcher)
    endif ()

    message(STATUS "build net_watcher? ${BUILD_NET_WATCHER}")
    if (BUILD_NET_WATCHER)
        add_subdirectory(net/net_watcher)
    endif ()

    message(STATUS "build delay_analysis? ${BUILD_DELAY_ANALYSIS}")
    if (BUILD_DELAY_ANALYSIS)
        add_subdirectory(net/delay_analysis)
    endif ()

    message(STATUS "build cpu_watcher? ${BUILD_CPU_WATCHER}")
    if (BUILD_CPU_WATCHER)
        add_subdirectory(process/cpu_watcher)
    endif ()

    message(STATUS "build proc_image? ${BUILD_PROC_IMAGE}")
    if (BUILD_PROC_IMAGE)
        add_subdirectory(process/proc_image)
    endif ()

    message(STATUS "build kvm_watcher? ${BUILD_KVM_WATCHER}")
    if (BUILD_KVM_WATCHER)
        add_subdirectory(hypervisor/kvm_watcher)
    endif ()

    message(STATUS "build stack_analyzer? ${BUILD_STACK_ANALYZER}")
    if (BUILD_STACK_ANALYZER)
        add_subdirectory(system_diagnosis/stack_analyzer)
    endif ()
    
    message(STATUS "build ipc_watcher? ${BUILD_IPC_WATCHER}")
    if (BUILD_IPC_WATCHER)
        add_subdirectory(ipc/ipc_watcher)
    endif ()
    message(STATUS "----------------------------------------")
endif ()



