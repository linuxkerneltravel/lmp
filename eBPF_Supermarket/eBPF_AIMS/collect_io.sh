#!/bin/bash
# stable_io_collect_final.sh
# 用途: 稳定采集磁盘/IO指标到 CSV 文件，每行一个时间戳+设备指标，列整齐

OUTPUT_FILE="./data/io_metrics.csv"
INTERVAL=1       # 采样间隔（秒）
COUNT=0          # 采样次数（0表示无限循环）

# 检查 iostat 是否安装
if ! command -v iostat &> /dev/null; then
    echo "iostat 未安装，请先安装 sysstat 包"
    exit 1
fi

# 写入表头
printf "%-20s %-10s %-8s %-12s %-12s %-10s %-10s\n" \
"timestamp" "device" "tps" "kB_read/s" "kB_wrtn/s" "kB_read" "kB_wrtn" > $OUTPUT_FILE

while true; do
    TIMESTAMP=$(date +"%Y-%m-%d %H:%M:%S")

    # 采集 iostat 输出，过滤非设备行（只匹配 sda、loop0 等设备）
    iostat -d -k $INTERVAL 2 | awk -v ts="$TIMESTAMP" '
        NF && ($1 ~ /^[a-z]+[0-9]*$/) {
            # 补齐空列
            for(i=2;i<=6;i++) if($i=="") $i=0
            printf "%-20s %-10s %-8s %-12s %-12s %-10s %-10s\n", ts, $1, $2, $3, $4, $5, $6
        }' >> $OUTPUT_FILE

    # 控制采样次数
    if [ $COUNT -gt 0 ]; then
        COUNT=$((COUNT-1))
        if [ $COUNT -eq 0 ]; then
            break
        fi
    fi
done
