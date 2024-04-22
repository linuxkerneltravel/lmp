set(CMAKE_SYSTEM_NAME Linux) #设置目标系统名字
set(CMAKE_SYSTEM_PROCESSOR arm64) #设置目标处理器架构

#设置libbpf和bpftool的make编译选项
set(CROSS_COMPILE "aarch64-linux-gnu-")

#检查交叉编译链是否存在于系统环境变量中,不存在报错结束
find_program(CMAKE_C_COMPILE_PATH NAMES ${CMAKE_C_COMPILER} PATHS $ENV{PATH})
find_program(CMAKE_CXX_COMPILE_PATH NAMES ${CMAKE_CXX_COMPILER} PATHS $ENV{PATH})
if(NOT CMAKE_C_COMPILE_PATH OR NOT CMAKE_CXX_COMPILE_PATH)
    message(FATAL_ERROR "Can't find aarch64 compiler, please add it to system environment variable!")
endif()

# 指定交叉编译链
set(CMAKE_C_COMPILER aarch64-linux-gnu-gcc)
set(CMAKE_CXX_COMPILER aarch64-linux-gnu-g++)
message(STATUS "The C compiler identification is ${CMAKE_C_COMPILER} now")
message(STATUS "The CXX compiler identification is ${CMAKE_CXX_COMPILER} now")

set(CC ${CMAKE_C_COMPILER})


#引入libbpf的依赖库zlib, elf
set(ZLIB_ARM64_DIR "${PROJECT_SOURCE_DIR}/platforms/aarch64/dependency/zlib-1.3.1/lib")
set(ELF_ARM64_DIR "${PROJECT_SOURCE_DIR}/platforms/aarch64/dependency/elfutils-0.189/lib")
set(ZLIB_SOURCE_DIR ${PROJECT_SOURCE_DIR}/platforms/aarch64/dependency/zlib-1.3.1/)
set(ELF_SOURCE_DIR ${PROJECT_SOURCE_DIR}/platforms/aarch64/dependency/elfutils-0.189/)
include_directories(
    ${ZLIB_SOURCE_DIR}/include
    ${ELF_SOURCE_DIR}/include)

message(STATUS "Arm64 cross-compilation set-up run successfully")
#bpf.c 使用clang编译，.c使用gcc编译