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
#      mem_watcher 工具 CMakeLists 文件
# -----------------------------------------------------------------------------------------
# TODO(fzy,2024.03.13): 名字应该为mem_watcher，page_fault可以作为功能块
set(TOOL_NAME mem_watcher)
set(TOOL_BELONG_TO_MODULE memory)

file(GLOB apps ${CMAKE_CURRENT_SOURCE_DIR}/bpf/*.bpf.c)
# 若不用Rust，则排除 profile.bpf.c
if(NOT CARGO_EXISTS)
    list(REMOVE_ITEM apps ${CMAKE_CURRENT_SOURCE_DIR}/bpf/profile.bpf.c)
endif()

# 设置并创建  <>/src-gen/TOOL_BELONG_TO_MODULE/TOOL_NAME 文件夹
set(SRC_GEN_TARGET_DIR ${CONFIG_SRC_GEN_DIR}/${TOOL_BELONG_TO_MODULE}/${TOOL_NAME})
if (NOT EXISTS ${SRC_GEN_TARGET_DIR})
    file(MAKE_DIRECTORY ${SRC_GEN_TARGET_DIR})
    message(STATUS "directory create success")
endif ()

# 遍历文件夹内所有的bpf.c
foreach(app ${apps})
    get_filename_component(app_stem ${app} NAME_WE)
    # Build object skeleton and depend skeleton on libbpf build
    bpf_object(${app_stem} ${app_stem}.bpf.c ${SRC_GEN_TARGET_DIR})
    add_dependencies(${app_stem}_skel libbpf-build bpftool-build)
endforeach()

add_executable(${TOOL_NAME} src/${TOOL_NAME}.c)
foreach (app ${apps})
    get_filename_component(app_stem ${app} NAME_WE)
    target_link_libraries(${TOOL_NAME} ${app_stem}_skel)

    if(${app_stem} STREQUAL "profile")
        target_include_directories(${app_stem} PRIVATE
                ${CMAKE_SOURCE_DIR}/blazesym/include)
        target_link_libraries(${app_stem}
                ${CMAKE_SOURCE_DIR}/blazesym/target/release/libblazesym.a -lpthread -lrt -ldl)
    endif()
endforeach ()

# 安装
# 设置安装目录
set(CPU_WATCHER_INSTALL_DIR backend/${TOOL_BELONG_TO_MODULE}/${TOOL_NAME}/)
install(TARGETS ${TOOL_NAME}
        RUNTIME DESTINATION ${CPU_WATCHER_INSTALL_DIR}/bin)



