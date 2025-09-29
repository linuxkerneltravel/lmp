#!/bin/sh
set -eu

# ================= 配置 =================
TARGET_DIR="/home/ubuntu/kaiyuan/code_test/libbpf-bootstrap/examples/c"
DURATION="${DURATION:-6}"   # 每个样例运行秒数
DO_BUILD="0"                # 不编译，直接跑
PARALLEL="${PARALLEL:-0}"   # 并行数（0=串行；并发下 dmesg 判定会变弱）

# 给特定样例附加参数：在 extra_args() 里按需添加
extra_args() {
  case "$1" in
    tc) echo "-i lo" ;;
    uprobe) echo "/bin/bash:read" ;;
    *) echo "" ;;
  esac
}

# 排除列表：非样例可执行/脚本/文档等
is_excluded() {
  case "$1" in
    .|..|Makefile|CMakeLists.txt|README|README.md|build|run_all_ebpf.sh|CMakeCache.txt|bpf|libbpf|src|include|__pycache__|*.sh|*.py|*.txt|*.md)
      return 0 ;;
    *)
      return 1 ;;
  esac
}

# 失败与良性关键字（合并为 ERE，避免用数组与 bash 语法）
FAIL_RE='(verifier .*fail|verifier .*error|verification failed|failed to [A-Za-z_ -]+|load BPF skeleton .*failed|BPF:.*invalid|Operation not permitted|permission denied|attach .* failed|link create failed|can'\''t( not)? attach|could not attach|no such file or directory|usdt .* failed)'
BENIGN_RE='(created successfully|relo #?[0-9]*: patched insn|skeleton .* created|prog '\''.*'\'': found map|object '\''.*'\''.*skipping optional step|linking.*ok|attached .* successfully)'

# 彩色（尽量简单，避免函数定义）
CG="\033[32m"; CR="\033[31m"; CY="\033[33m"; CB="\033[36m"; CN="\033[0m"

need_root() {
  if [ "$(id -u)" -ne 0 ]; then
    printf "${CR}[ERR] 请用 sudo 运行此脚本。${CN}\n"
    exit 1
  fi
}

collect_candidates() {
  # 仅收集当前目录下一层的可执行文件，写到 .candidates.list
  : > .candidates.list
  find . -maxdepth 1 -type f -perm -u+x -printf '%f\n' | sort | while IFS= read -r f; do
    if is_excluded "$f"; then
      continue
    fi
    case "$f" in
      *.sh|*.py|*.txt|*.md) continue ;;
    esac
    echo "$f" >> .candidates.list
  done
}

maybe_build() {
  if [ "$DO_BUILD" = "1" ] && [ -f Makefile ]; then
    printf "${CB}[BUILD] make -j$(nproc) ...${CN}\n"
    if ! make -j"$(nproc)"; then
      printf "${CY}[WARN] make 失败，继续尝试已有可执行文件。${CN}\n"
    fi
  fi
}

snapshot_dmesg() {
  # 返回可读时间戳（用于 --since），失败返回空
  date +"%Y-%m-%d %H:%M:%S" 2>/dev/null || echo ""
}

dmesg_delta() {
  since_ts="$1"
  # 检查 --since 是否可用
  if dmesg --help 2>&1 | grep -q -- "--since" && [ -n "$since_ts" ]; then
    dmesg -T --since "$since_ts" || true
  else
    echo ""
  fi
}

# 返回 0 表示“明确失败”；1 表示“未判定失败”
judge_failure_precise() {
  content="$1"

  # 若没有出现任何失败短语，直接非失败
  echo "$content" | grep -Eiq "$FAIL_RE" || return 1

  # 取最后 60 行，若其中存在一行匹配 FAIL_RE 且不匹配 BENIGN_RE，则判失败
  echo "$content" | tail -n 60 | awk -v fail_re="$FAIL_RE" -v ok_re="$BENIGN_RE" '
    BEGIN { rc=1 }
    {
      line=$0
    }
    {
      # awk 不支持 ERE 组名，直接传给系统的 grep 更稳妥
      cmd1="printf \"%s\n\" " q line q " | grep -Eiq \"" fail_re "\""; 
      cmd2="printf \"%s\n\" " q line q " | grep -Eiq \"" ok_re "\"";
    }
    function run(cmd){ return system(cmd); }
    {
      # run(cmd)==0 表示匹配
      if (run(cmd1)==0 && run(cmd2)!=0) { rc=0; exit }
    }
    END { exit rc }
  ' q="'" && return 0 || return 1
}

run_one() {
  prog="$1"
  args="$(extra_args "$prog")"
  log_dir=".run_logs"
  mkdir -p "$log_dir"
  out="$log_dir/${prog}.out.log"
  err="$log_dir/${prog}.err.log"
  : >"$out"; : >"$err"

  printf "${CB}▶ 运行：%s %s  (timeout=%ss)${CN}\n" "$prog" "$args" "$DURATION"
  d_since="$(snapshot_dmesg)"

  # 降低 libbpf 噪声
  set +e
  LIBBPF_LOG_LEVEL=warn timeout --signal=INT "$DURATION" "./$prog" $args >"$out" 2>"$err"
  rc=$?
  set -e

  dmsg="$(dmesg_delta "$d_since")"
  # 合并用于判定
  combined="$(cat "$out"; echo; cat "$err"; echo; echo "$dmsg")"

  verdict=""
  note=""

  if judge_failure_precise "$combined"; then
    verdict="FAIL"; note="检测到明确失败短语"
  else
    if [ $rc -eq 0 ]; then
      verdict="OK"
    elif [ $rc -eq 124 ]; then
      verdict="OK"; note="timeout 截止（可能是常驻样例）"
    else
      verdict="FAIL?"; note="exit=$rc 但未见明确失败短语（建议复核）"
    fi
  fi

  if [ "$verdict" = "OK" ]; then
    printf "${CG}✔ %s 运行成功%s${CN}\n" "$prog" "${note:+ ($note)}"
  elif [ "$verdict" = "FAIL?" ]; then
    printf "${CY}⁉ %s 可能失败%s${CN}\n" "$prog" "${note:+ ($note)}"
  else
    printf "${CR}✘ %s 运行失败%s${CN}\n" "$prog" "${note:+ ($note)}"
  fi

  printf "  ├─ stdout: %s 行，stderr: %s 行\n" "$(wc -l <"$out")" "$(wc -l <"$err")"
  if [ -s "$err" ]; then
    echo "  ├─ stderr 结尾："
    tail -n 3 "$err" | sed 's/^/  │   /'
  fi
  if [ -n "$dmsg" ]; then
    echo "  └─ dmesg 增量（BPF相关摘取）："
    echo "$dmsg" | grep -Ei "bpf|verifier|prog|map" | tail -n 5 | sed 's/^/      /' || true
  fi

  # 返回码：OK=0，FAIL?=2，FAIL=1
  if [ "$verdict" = "OK" ]; then
    return 0
  elif [ "$verdict" = "FAIL?" ]; then
    return 2
  else
    return 1
  fi
}

main() {
  need_root
  cd "$TARGET_DIR"
  printf "${CB}[INFO] 目标目录：%s${CN}\n" "$TARGET_DIR"
  maybe_build
  collect_candidates

  if [ ! -s .candidates.list ]; then
    printf "${CR}[ERR] 未发现可执行样例文件。${CN}\n"
    exit 1
  fi

  printf "${CB}[INFO] 待测样例：${CN}\n"
  sed 's/^/ - /' .candidates.list

  ok=0; fail=0; unsure=0

  if [ "$PARALLEL" -gt 0 ]; then
    # 并行（不统计总数）
    # shellcheck disable=SC2016
    xargs -I{} -P "$PARALLEL" sh -c '
      . ./'"$(basename "$0")"'
    ' < /dev/null 2>/dev/null || true
    printf "${CY}[WARN] 并行模式下不统计成功/失败总数，请查看滚动输出与 .run_logs/。${CN}\n"
  else
    # 串行统计
    while IFS= read -r p; do
      if run_one "$p"; then
        ok=$((ok+1))
      else
        rc=$?
        if [ $rc -eq 2 ]; then
          unsure=$((unsure+1))
        else
          fail=$((fail+1))
        fi
      fi
      echo
    done < .candidates.list

    printf "${CB}======= 汇总 =======${CN}\n"
    echo "成功：$ok"
    echo "失败：$fail"
    echo "可能失败（需复核）：$unsure"
    echo "日志目录：$TARGET_DIR/.run_logs"
  fi
}

main "$@"
