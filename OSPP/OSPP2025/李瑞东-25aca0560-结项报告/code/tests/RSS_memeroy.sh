#!/usr/bin/env bash
# 用程序名 -> 找到最近的 PID -> pidstat 连续采样 -> 计算均值（不依赖 "Average:" 行）
# 用法: ./test.sh <prog_name> <duration_sec> [interval_sec]
# 例子: ./test.sh bootstrap 60 1

set -euo pipefail

if [ $# -lt 2 ]; then
  echo "用法: $0 <程序名> <持续秒数> [采样间隔秒，默认1]"
  exit 1
fi

APP="$1"
DURATION="$2"
INTERVAL="${3:-1}"

# 找“最近启动”的那个 PID（同名多进程时最常用）
PID="$(pgrep -n "$APP" || true)"
if [ -z "$PID" ]; then
  echo "未找到名为 '$APP' 的进程"
  exit 1
fi

echo "目标进程: $APP (PID=$PID), 每${INTERVAL}s采样，共${DURATION}s ..."

# 强制英文环境，避免本地化改变列名/关键字
export LC_ALL=C LANG=C

# 计算采样次数
COUNT=$(( DURATION / INTERVAL ))
if [ "$COUNT" -le 0 ]; then
  COUNT=1
fi

# 运行 pidstat 并解析“每次采样行”，累加 VSZ/RSS（单位 kB），最后输出均值
# pidstat -r 输出的每行格式大致为：
# <time> <UID> <PID> <minflt/s> <majflt/s> <VSZ> <RSS> <%MEM> <Command>
# 我们用 $3 (PID)、$6 (VSZ kB)、$7 (RSS kB)
sudo pidstat -r -p "$PID" "$INTERVAL" "$COUNT" 2>/dev/null | \
awk -v TARGET="$PID" '
  BEGIN { n=0; sum_rss=0; sum_vsz=0; }
  # 过滤掉标题/空行/包含非数据的行，只处理 PID 列等于目标 PID 的数据行
  /^[0-9]/ || $1 ~ /^[0-9]{2}:[0-9]{2}:[0-9]{2}/ {
    # 既兼容前面带日期时间，也兼容只有时间的情况
    # 常见为：TIME UID PID minflt/s majflt/s VSZ RSS %MEM Command
    if ($3 == TARGET) {
      vsz_kb = $6 + 0
      rss_kb = $7 + 0
      if (vsz_kb > 0 && rss_kb >= 0) {
        sum_vsz += vsz_kb
        sum_rss += rss_kb
        n++
      }
    }
  }
  END {
    if (n == 0) {
      print "没有采到有效样本（进程可能过早退出，或权限/本地化导致解析失败）"
      exit 2
    }
    avg_vsz = sum_vsz / n
    avg_rss = sum_rss / n
    printf("样本数=%d  平均VSZ=%.0f kB  平均RSS=%.0f kB\n", n, avg_vsz, avg_rss)
  }'
