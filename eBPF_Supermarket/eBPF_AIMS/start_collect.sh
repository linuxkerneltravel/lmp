#!/bin/bash
[ "$EUID" -ne 0 ] && { echo "请用 sudo 运行"; exit 1; }
ulimit -l unlimited
# start_collect.sh
# 启动 CPU、MEM、IO、NET 采集脚本，并后台运行

# 启动采集脚本
./collect_cpu.sh &
PID_CPU=$!

./collect_mem.sh &
PID_MEM=$!

./collect_io.sh &
PID_IO=$!

./collect_net.sh &
PID_NET=$!

# 先编译 eBPF 监听端，失败则退出
if ! ( cd collect && make -s all >/dev/null 2>&1 ); then
  echo "编译 eBPF 监听端失败，请安装 clang、make、libelf 等依赖"
  exit 1
fi

# 启动 eBPF 监听端（collect/main）
(
  cd collect && ./main
) &
PID_BPF=$!

# 等待 Socket 准备好，避免 Python 先发导致 Connection refused
for i in {1..40}; do
  if [ -S /tmp/bpf_trigger.sock ]; then
    break
  fi
  sleep 0.5
done

# 启动实时 ML 监控（流式）
python3 ./ml/realtime_monitor.py &
PID_ML=$!

echo "所有采集脚本已启动："
echo "CPU PID: $PID_CPU"
echo "MEM PID: $PID_MEM"
echo "IO PID: $PID_IO"
echo "NET PID: $PID_NET"
echo "BPF PID: $PID_BPF"
echo "ML  PID: $PID_ML"
echo "按 Ctrl+C 停止所有采集"

# 捕获 Ctrl+C 信号，终止所有采集
trap "echo '停止所有采集...'; kill $PID_CPU $PID_MEM $PID_IO $PID_NET $PID_BPF $PID_ML; exit 0" SIGINT

# 等待后台进程
wait
