#!/bin/sh
dir=/sys/kernel/debug/tracing
sysctl kernel.ftrace_enabled=1
echo 0 > ${dir}/tracing_on
echo nop  > ${dir}/current_tracer
echo function_graph > ${dir}/current_tracer  
# echo vfs_write > ${dir}/set_graph_function 
echo 335164 > ${dir}/set_ftrace_pid
# echo 1 > ${dir}/events/syscalls/sys_enter_write/enable
echo 1 > ${dir}/tracing_on
sleep 8
echo 0 > ${dir}/tracing_on
less ${dir}/trace -o tx_trace.txt
