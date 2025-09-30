#!/bin/bash
# vmstat_mem_collect.sh
# 用途: 使用 vmstat 或 free 采集内存指标，并输出到 CSV 文件

OUTPUT_FILE="./data/mem_metrics.csv"
INTERVAL=1       # 采样间隔（秒）
COUNT=0          # 采样次数（0表示无限循环）

# 写入表头
printf "%-20s %-10s %-10s %-10s %-10s %-10s %-10s\n" "timestamp" "total_MB" "used_MB" "free_MB" "buff_cache_MB" "swap_total_MB" "swap_used_MB" > $OUTPUT_FILE

while true; do
    TIMESTAMP=$(date +"%Y-%m-%d %H:%M:%S")

    # 使用 free 命令获取内存数据
    MEM_STATS=$(free -m | awk 'NR==2{total=$2; used=$3; free=$4; buff=$6} NR==3{swap_total=$2; swap_used=$3} END{print total,used,free,buff,swap_total,swap_used}')

    read TOTAL USED FREE BUFF_SWAP SWAP_TOTAL SWAP_USED <<< $MEM_STATS

    # 输出到 CSV 文件
    printf "%-20s %-10s %-10s %-10s %-10s %-10s %-10s\n" "$TIMESTAMP" "$TOTAL" "$USED" "$FREE" "$BUFF_SWAP" "$SWAP_TOTAL" "$SWAP_USED" >> $OUTPUT_FILE

    # 控制采样次数
    if [ $COUNT -gt 0 ]; then
        COUNT=$((COUNT-1))
        if [ $COUNT -eq 0 ]; then
            break
        fi
    fi

    sleep $INTERVAL
done
