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
#      net_watcher 工具 CMakeLists 文件
# -----------------------------------------------------------------------------------------
set(TOOL_NAME net_watcher)
set(TOOL_BELONG_TO_MODULE net)

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

# 将可执行文件，配置文件等安装在对应的位置
# 设置安装目录
set(CPU_WATCHER_INSTALL_DIR backend/${TOOL_BELONG_TO_MODULE}/${TOOL_NAME})
# 安装可执行文件到 ${CPU_WATCHER_INSTALL_DIR}/bin
install(TARGETS ${TOOL_NAME}
        RUNTIME DESTINATION ${CPU_WATCHER_INSTALL_DIR}/bin)
# 安装配置文件到 ${CPU_WATCHER_INSTALL_DIR}/etc

# 获取内核版本信息
execute_process(
    COMMAND uname -r  # 运行命令 'uname -r' 来获取内核版本
    OUTPUT_VARIABLE VERSION_INFO  # 将输出结果存储在变量 VERSION_INFO 中
    OUTPUT_STRIP_TRAILING_WHITESPACE  # 去除输出末尾的空白字符
)

# 输出原始内核版本信息
message(STATUS "Raw Kernel Version: ${VERSION_INFO}")

# 使用 '-' 分隔版本信息，存储到 VERSION_PARTS 列表中
string(REPLACE "-" ";" VERSION_PARTS ${VERSION_INFO})

list(GET VERSION_PARTS 0 VERSION_BASE)

# 从 VERSION_BASE 中提取主、次和补丁版本号
string(REPLACE "." ";" VERSION_NUMBERS ${VERSION_BASE})  # 用 '.' 分隔
list(GET VERSION_NUMBERS 0 VERSION_MAJOR)  # 获取主版本号
list(GET VERSION_NUMBERS 1 VERSION_MINOR)  # 获取次版本号
list(GET VERSION_NUMBERS 2 VERSION_PATCH)  # 获取补丁版本号

# 输出解析后的版本号信息
message(STATUS "Kernel Major: ${VERSION_MAJOR}, Minor: ${VERSION_MINOR}, Patch: ${VERSION_PATCH}")

# 定义最小支持的版本
set(MIN_MAJOR 6)  # 最小主版本号
set(MIN_MINOR 4)  # 最小次版本号
set(MIN_PATCH 0)  # 最小补丁版本号

# 根据版本比较结果来定义宏
if(VERSION_MAJOR GREATER ${MIN_MAJOR} OR  # 如果主版本号大于最小主版本号
   (VERSION_MAJOR EQUAL ${MIN_MAJOR} AND VERSION_MINOR GREATER ${MIN_MINOR}) OR  # 或者主版本号等于最小主版本号且次版本号大于最小次版本号
   (VERSION_MAJOR EQUAL ${MIN_MAJOR} AND VERSION_MINOR EQUAL ${MIN_MINOR} AND VERSION_PATCH GREATER_EQUAL ${MIN_PATCH}))  # 或者主、次版本号均相等且补丁版本号大于或等于最小补丁版本号
    add_definitions(-DUSE_NEW_GET_USER_DATA)  # 如果满足条件，则定义宏 USE_NEW_GET_USER_DATA
endif()
