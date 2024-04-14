#!/bin/bash
# 按照时间从大到小排序打印进程pid和comm，只打印前10条
ps -eo pid,comm,time --sort=-time | head -n 10