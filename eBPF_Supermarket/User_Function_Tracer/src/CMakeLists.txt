SET(app utrace.bpf.c)
get_filename_component(app_stem ${app} NAME_WE)

bpf_object(${app_stem} ${app_stem}.bpf.c)
add_dependencies(${app_stem}_skel libbpf-build bpftool-build)

file(GLOB_RECURSE srcs CONFIGURE_DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/*.c)
list(REMOVE_ITEM srcs ${CMAKE_CURRENT_SOURCE_DIR}/${app_stem}.bpf.c ${CMAKE_CURRENT_SOURCE_DIR}/${app_stem}.c)
add_executable(${app_stem} ${app_stem}.c ${srcs})

target_compile_options(${app_stem} PUBLIC -Wall -Wextra)

target_link_options(${app_stem} PUBLIC -lstdc++ -lelf)
target_link_libraries(${app_stem} PUBLIC ${app_stem}_skel)
