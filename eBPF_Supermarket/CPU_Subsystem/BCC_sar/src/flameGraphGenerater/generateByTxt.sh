#!/bin/bash
# 第一个参数是提供给flameGraph生成程序的格式化文本，第二个参数是生成的svg图形的path
../perf_data/FlameGraph/flamegraph.pl --hash $1 > $2
