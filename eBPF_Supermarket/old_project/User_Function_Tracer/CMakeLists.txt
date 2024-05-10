cmake_minimum_required(VERSION 3.16)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

project(eBPF-utrace
  DESCRIPTION "eBPF Based User Function Tracer"
  LANGUAGES C
)

# we use abi::__cxa_demangle(), which is only availabel on clang
SET(CMAKE_C_COMPILER /usr/bin/clang CACHE STRING "C compiler" FORCE)

list(APPEND CMAKE_MODULE_PATH ${CMAKE_CURRENT_SOURCE_DIR}/tools/cmake)

set(BPFOBJECT_VMLINUX_H ${CMAKE_CURRENT_SOURCE_DIR}/vmlinux/vmlinux.h)

find_package(BpfObject REQUIRED)
find_package(LibBpf REQUIRED)

set(EXECUTABLE_OUTPUT_PATH ${CMAKE_SOURCE_DIR}/build)

add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/src)

# format target
file(GLOB
  FILES_NEED_FORMAT
  CONFIGURE_DEPENDS
  "src/*.c"
  "src/*.h"
  "test/*.c"
  "test/*.cpp"
)

add_custom_target(format
  COMMAND clang-format --style=file -i ${FILES_NEED_FORMAT}
  COMMENT "Running clang-format."
  VERBATIM
)

# doc target
add_custom_target(doc 
  COMMAND doxygen ${CMAKE_CURRENT_SOURCE_DIR}/Doxyfile
  COMMENT "Generating docs."
  WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
  VERBATIM
)
