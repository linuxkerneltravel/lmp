#!/bin/bash

# --- 配置参数 ---
DB_NAME="sbtest"
DB_USER="sbuser"
DB_PASS="your_password" # <--- 在这里填入你的数据库密码
TABLES=16
TABLE_SIZE=1000000
DURATION=120 # 测试时长，单位秒
REPORT_INTERVAL=10 # 每隔10秒报告一次中间结果

# 获取系统 CPU 核心数
CPU_CORES=$(nproc)

# 定义并发线程数数组，覆盖不同压力级别
# 从低于核心数，到等于核心数，再到远超核心数
# THREAD_LEVELS=($(($CPU_CORES / 2)) $CPU_CORES $(($CPU_CORES * 2)) $(($CPU_CORES * 4)))
THREAD_LEVELS=($(($CPU_CORES * 4)))

# 输出结果的目录
RESULTS_DIR="benchmark_results_$(date +%F_%H-%M-%S)"
mkdir -p "$RESULTS_DIR"

# --- 辅助函数 ---
function run_sysbench_test() {
    local scheduler_name=$1
    local threads=$2
    local output_file="$RESULTS_DIR/${scheduler_name}_${threads}threads.txt"

    echo "=============================================================="
    echo "Running test: Scheduler=$scheduler_name, Threads=$threads"
    echo "Output will be saved to: $output_file"
    echo "=============================================================="

    sysbench oltp_read_write \
      --mysql-db=$DB_NAME \
      --mysql-user=$DB_USER \
      --mysql-password=$DB_PASS \
      --tables=$TABLES \
      --table-size=$TABLE_SIZE \
      --threads=$threads \
      --time=$DURATION \
      --report-interval=$REPORT_INTERVAL \
      run | tee "$output_file"
    
    echo "Test finished for Scheduler=$scheduler_name, Threads=$threads."
    sleep 5 # 测试间隔
}

# --- 主执行流程 ---

# 确保 MySQL 服务正在运行
sudo systemctl start mysql

# --- 测试 CFS (基线) ---
echo " "
echo "********** STARTING BENCHMARK FOR CFS SCHEDULER **********"
# 确保没有 sched_ext 调度器在运行
# （如果之前运行过，可能需要手动 kill 掉 scx_simple 进程）
pkill scx_simple || true
sleep 2

for threads in "${THREAD_LEVELS[@]}"; do
    run_sysbench_test "cfs" "$threads"
done

echo "********** FINISHED BENCHMARK FOR CFS SCHEDULER **********"
echo " "


# --- 测试 scx_simple (实验组) ---
echo " "
echo "********** STARTING BENCHMARK FOR scx_simple SCHEDULER **********"
# 在后台启动 scx_simple 调度器
sudo ../tools/sched_ext/build/bin/scx_simple > "$RESULTS_DIR/scx_simple_log.txt" 2>&1 &
SCX_PID=$!
echo "scx_simple scheduler started with PID $SCX_PID. Waiting for it to stabilize..."
sleep 5 # 等待调度器完全接管系统

# 检查调度器是否成功启动
if ! ps -p $SCX_PID > /dev/null; then
   echo "Failed to start scx_simple scheduler. Check logs."
   exit 1
fi

for threads in "${THREAD_LEVELS[@]}"; do
    run_sysbench_test "scx_simple" "$threads"
done

# 停止 scx_simple 调度器
echo "Stopping scx_simple scheduler..."
sudo kill -SIGINT $SCX_PID
wait $SCX_PID 2>/dev/null
echo "scx_simple scheduler stopped."
echo "********** FINISHED BENCHMARK FOR scx_simple SCHEDULER **********"


echo " "
echo "All benchmarks completed. Results are in the '$RESULTS_DIR' directory."
