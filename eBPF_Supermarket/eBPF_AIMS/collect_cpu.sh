#!/bin/bash
# vmstat_cpu_collect.sh
# 用途: 使用 vmstat 采集 CPU 基础指标，并输出到 CSV 文件
# CPU 指标: 用户态 (us), 系统态 (sy), 空闲 (id), IO等待 (wa), 硬中断 (hi), 软中断 (si)

# 输出文件
OUTPUT_FILE="./data/cpu_metrics.csv"

# 采样间隔（秒）
INTERVAL=1

# 采样次数（0表示无限循环）
COUNT=0

# 写入表头
printf "%-20s %-3s %-3s %-3s %-3s %-3s %-3s\n" "timestamp" "us" "sy" "id" "wa" "hi" "si" > $OUTPUT_FILE

# 无限循环采集（或指定次数）
while true; do
    # 当前时间
    TIMESTAMP=$(date +"%Y-%m-%d %H:%M:%S")
    
    # 使用 vmstat 获取 CPU 指标（第13-18列）
    CPU_STATS=$(vmstat $INTERVAL 2 | tail -1 | awk '{print $13,$14,$15,$16,$17,$18}')
    
    # 拆分字段，保证 si 不为空
    read US SY ID WA HI SI <<< $CPU_STATS
    SI=${SI:-0}  # 如果 si 为空，则补 0

    # 写入 CSV 文件，列固定宽度对齐
    printf "%-20s %-3s %-3s %-3s %-3s %-3s %-3s\n" "$TIMESTAMP" "$US" "$SY" "$ID" "$WA" "$HI" "$SI" >> $OUTPUT_FILE

    # 如果有指定次数则退出
    if [ $COUNT -gt 0 ]; then
        COUNT=$((COUNT-1))
        if [ $COUNT -eq 0 ]; then
            break
        fi
    fi
done
