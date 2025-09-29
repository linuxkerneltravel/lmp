#!/bin/bash
# net_metrics_collect.sh
# 用途: 采集网络接口指标到 CSV，每行一个时间戳+网卡指标

OUTPUT_FILE="./data/net_metrics.csv"
INTERVAL=1       # 采样间隔（秒）
COUNT=0          # 采样次数（0表示无限循环）

# 写入表头
printf "%-20s %-10s %-12s %-12s %-12s %-12s %-10s %-10s\n" \
"timestamp" "iface" "rx_bytes/s" "tx_bytes/s" "rx_packets/s" "tx_packets/s" "rx_errs/s" "tx_errs/s" > $OUTPUT_FILE

# 获取初始值
PREV_STATS=$(cat /proc/net/dev | tail -n +3)

while true; do
    TIMESTAMP=$(date +"%Y-%m-%d %H:%M:%S")
    sleep $INTERVAL

    CUR_STATS=$(cat /proc/net/dev | tail -n +3)

    # 遍历每个接口
    echo "$CUR_STATS" | while read line; do
        iface=$(echo $line | awk -F: '{print $1}' | xargs)
        rx_bytes=$(echo $line | awk -F: '{print $2}' | awk '{print $1}')
        tx_bytes=$(echo $line | awk -F: '{print $2}' | awk '{print $9}')
        rx_packets=$(echo $line | awk -F: '{print $2}' | awk '{print $2}')
        tx_packets=$(echo $line | awk -F: '{print $2}' | awk '{print $10}')
        rx_errs=$(echo $line | awk -F: '{print $2}' | awk '{print $3}')
        tx_errs=$(echo $line | awk -F: '{print $2}' | awk '{print $11}')

        # 计算每秒增量
        prev_line=$(echo "$PREV_STATS" | grep "$iface")
        if [ -n "$prev_line" ]; then
            prev_rx_bytes=$(echo $prev_line | awk -F: '{print $2}' | awk '{print $1}')
            prev_tx_bytes=$(echo $prev_line | awk -F: '{print $2}' | awk '{print $9}')
            prev_rx_packets=$(echo $prev_line | awk -F: '{print $2}' | awk '{print $2}')
            prev_tx_packets=$(echo $prev_line | awk -F: '{print $2}' | awk '{print $10}')
            prev_rx_errs=$(echo $prev_line | awk -F: '{print $2}' | awk '{print $3}')
            prev_tx_errs=$(echo $prev_line | awk -F: '{print $2}' | awk '{print $11}')

            rx_bytes_s=$(( (rx_bytes - prev_rx_bytes)/INTERVAL ))
            tx_bytes_s=$(( (tx_bytes - prev_tx_bytes)/INTERVAL ))
            rx_packets_s=$(( (rx_packets - prev_rx_packets)/INTERVAL ))
            tx_packets_s=$(( (tx_packets - prev_tx_packets)/INTERVAL ))
            rx_errs_s=$(( (rx_errs - prev_rx_errs)/INTERVAL ))
            tx_errs_s=$(( (tx_errs - prev_tx_errs)/INTERVAL ))
        else
            rx_bytes_s=0
            tx_bytes_s=0
            rx_packets_s=0
            tx_packets_s=0
            rx_errs_s=0
            tx_errs_s=0
        fi

        printf "%-20s %-10s %-12s %-12s %-12s %-12s %-10s %-10s\n" \
        "$TIMESTAMP" "$iface" "$rx_bytes_s" "$tx_bytes_s" "$rx_packets_s" "$tx_packets_s" "$rx_errs_s" "$tx_errs_s" >> $OUTPUT_FILE
    done

    PREV_STATS="$CUR_STATS"

    # 控制采样次数
    if [ $COUNT -gt 0 ]; then
        COUNT=$((COUNT-1))
        if [ $COUNT -eq 0 ]; then
            break
        fi
    fi
done
