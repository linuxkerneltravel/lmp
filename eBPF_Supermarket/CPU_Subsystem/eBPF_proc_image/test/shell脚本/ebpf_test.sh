#!/bin/bash
SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
OUTPUT_DIR="$SCRIPT_DIR/lttng-traces"
# 获取目标进程的 PID
TARGET_PID=$(pidof test_proc_image)

if [ -z "$TARGET_PID" ]; then
    echo "目标进程未运行，请先启动目标进程。"
    exit 1
fi
echo "测试程序 PID: $TARGET_PID"
# 运行 eBPF 程序并将输出重定向到文件

cd /home/xhb/lmp2/lmp/eBPF_Supermarket/CPU_Subsystem/eBPF_proc_image/
sudo ./proc_image -k > $OUTPUT_DIR/output.log &
PROC_IMAGE_PID=$!
sleep 1
sudo ./controller -k 0 -p $TARGET_PID -a
# echo "eBPF 程序已在后台运行，输出将保存到 $OUTPUT_DIR/output.log 中 请在数据收集完后 Ctrl+C。"
read
sudo ./controller -k 0 -p $TARGET_PID -d
# 捕捉 Ctrl + C 信号
# trap "echo '捕捉到 Ctrl + C 信号，停止进程...'; kill -SIGINT $PROC_IMAGE_PID; exit 0" SIGINT
# kill -SIGINT $PROC_IMAGE_PID
sudo ./controller -k 0 -f
echo "eBPF 程序已在后台运行，输出将保存到`$OUTPUT_DIR/output.log` 中"

