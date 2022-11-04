#!/bin/bash
sudo perf record -F 99 -a -g -- sleep 2
sudo perf report -n --stdio > perf_output.txt

