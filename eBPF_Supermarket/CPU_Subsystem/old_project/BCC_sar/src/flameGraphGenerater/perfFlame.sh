#!/bin/bash
time=4
freq=49
# perf得到的函数调用占用时间图转换为svg格式的火焰图
# INPUT: 输出的svg文件的名称
sudo perf record -F $freq -ag -- sleep $time
sudo perf script --header | ./FlameGraph/stackcollapse-perf.pl | ./FlameGraph/flamegraph.pl > $1
# $1 is svg file name