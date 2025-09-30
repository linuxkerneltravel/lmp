import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
import socket
import time
from pathlib import Path
import os
import sys

# === 路径与环境变量 ===
PROJECT_ROOT = Path(__file__).resolve().parents[1]
DATA_DIR = Path(os.environ.get("AIMS_DATA_DIR", str(PROJECT_ROOT / "data")))
ML_DIR = PROJECT_ROOT / "ml"

CPU_FILE = DATA_DIR / "cpu_metrics.csv"
MEM_FILE = DATA_DIR / "mem_metrics.csv"
IO_FILE  = DATA_DIR / "io_metrics.csv"
NET_FILE = DATA_DIR / "net_metrics.csv"

SOCKET_PATH = os.environ.get("AIMS_SOCKET_PATH", "/tmp/bpf_trigger.sock")
PREFERRED_IFACE = os.environ.get("AIMS_NET_IFACE")

OUTPUT_FILE = ML_DIR / "metrics_with_bpf.csv"
FEATURES_SEED = ML_DIR / "metrics_features.csv"  # 作为初始训练集的种子

# 将 stdout/stderr 同时写入终端与固定日志文件
LOGS_DIR = PROJECT_ROOT / "logs"
LOGS_DIR.mkdir(parents=True, exist_ok=True)
LOG_FILE = LOGS_DIR / "realtime_monitor.log"

class _StreamTee:
    def __init__(self, streams):
        self._streams = streams
    def write(self, data):
        for s in self._streams:
            try:
                s.write(data)
                s.flush()
            except Exception:
                pass
    def flush(self):
        for s in self._streams:
            try:
                s.flush()
            except Exception:
                pass

_orig_out, _orig_err = sys.stdout, sys.stderr
_log_fp = open(LOG_FILE, "a", encoding="utf-8", buffering=1)
sys.stdout = _StreamTee([_orig_out, _log_fp])
sys.stderr = _StreamTee([_orig_err, _log_fp])
print(f"日志同时输出到终端与文件: {LOG_FILE}")

# 维度判定阈值（标准化后的绝对 z 分数阈值）- 降低阈值加速检测
DIM_Z_THRESHOLD = float(os.environ.get("AIMS_DIM_Z", "2.0"))
# 模型异常比例（可调高以更敏感，比如 0.15）- 提高敏感度
CONTAMINATION = float(os.environ.get("AIMS_CONTAMINATION", "0.1"))
# 异常时若未超过阈值，回退显示的前 K 个维度数
DIM_TOPK = int(os.environ.get("AIMS_DIM_TOPK", "2"))
# 正常状态连续 N 次后自动关闭 NET 打印 - 减少等待次数
NET_OFF_AFTER_NORMAL = int(os.environ.get("AIMS_NET_OFF_AFTER_NORMAL", "2"))

cpu_features = ["cpu_usage","cpu_wait"]
mem_features = ["mem_usage"]
io_features  = ["io_tps","io_read","io_write"]
net_features = ["net_in","net_out"]
all_features = cpu_features + mem_features + io_features + net_features

# === 工具函数 ===
def load_csv_space(path: Path) -> pd.DataFrame:
    df = pd.read_csv(path, delim_whitespace=True)
    df.columns = df.columns.str.strip().str.replace('/', '_')
    df["timestamp"] = pd.to_datetime(df["timestamp"])
    return df

def build_features_from_full() -> pd.DataFrame:
    """从完整 CSV 构建全量特征（用于初始训练集）。"""
    df_cpu = load_csv_space(CPU_FILE)
    df_mem = load_csv_space(MEM_FILE)
    df_io  = load_csv_space(IO_FILE)
    df_net = load_csv_space(NET_FILE)

    df_cpu["cpu_usage"] = df_cpu["us"] + df_cpu["sy"]
    df_cpu["cpu_wait"]  = df_cpu["wa"]
    cpu_feat = df_cpu[["timestamp","cpu_usage","cpu_wait"]]

    df_mem["mem_usage"] = df_mem["used_MB"] / df_mem["total_MB"].replace(0, np.nan)
    df_mem["mem_usage"] = df_mem["mem_usage"].fillna(0)
    mem_feat = df_mem[["timestamp","mem_usage"]]

    # 过滤 loop/sr，按时间聚合
    df_io = df_io[~df_io["device"].astype(str).str.startswith(("loop","sr"))]
    io_agg = (
        df_io.groupby("timestamp")
        .agg({"tps":"sum","kB_read_s":"sum","kB_wrtn_s":"sum"})
        .reset_index()
    )
    io_feat = io_agg.rename(columns={
        "tps":"io_tps","kB_read_s":"io_read","kB_wrtn_s":"io_write"
    })

    # 选择主要网卡
    df_net = df_net.copy()
    if PREFERRED_IFACE:
        df_net = df_net[df_net["iface"] == PREFERRED_IFACE]
    else:
        df_net = df_net[df_net["iface"] != "lo"]
        if not df_net.empty:
            traffic_by_iface = (
                df_net.groupby("iface")[ ["rx_bytes_s","tx_bytes_s"] ].sum().sum(axis=1)
            )
            primary_iface = traffic_by_iface.idxmax()
            df_net = df_net[df_net["iface"] == primary_iface]
    net_feat = df_net[["timestamp","rx_bytes_s","tx_bytes_s"]].rename(
        columns={"rx_bytes_s":"net_in","tx_bytes_s":"net_out"}
    )

    df = cpu_feat.merge(mem_feat, on="timestamp", how="inner")
    df = df.merge(io_feat, on="timestamp", how="inner")
    df = df.merge(net_feat, on="timestamp", how="inner")
    return df.sort_values("timestamp")


def build_features_latest_row() -> pd.DataFrame:
    """从每个 CSV 的最新时间片构建单行特征。"""
    df_cpu = load_csv_space(CPU_FILE)
    df_mem = load_csv_space(MEM_FILE)
    df_io  = load_csv_space(IO_FILE)
    df_net = load_csv_space(NET_FILE)

    # 最新时间戳（逐表）
    ts_cpu = df_cpu["timestamp"].max()
    ts_mem = df_mem["timestamp"].max()
    ts_io  = df_io["timestamp"].max()
    ts_net = df_net["timestamp"].max()

    # CPU 特征（取最新一行）
    last_cpu = df_cpu[df_cpu["timestamp"] == ts_cpu].tail(1).copy()
    last_cpu["cpu_usage"] = last_cpu["us"].fillna(0) + last_cpu["sy"].fillna(0)
    last_cpu["cpu_wait"]  = last_cpu["wa"].fillna(0)
    cpu_feat = last_cpu[["timestamp","cpu_usage","cpu_wait"]]

    # MEM 特征
    last_mem = df_mem[df_mem["timestamp"] == ts_mem].tail(1).copy()
    last_mem["mem_usage"] = (
        last_mem["used_MB"].fillna(0) / last_mem["total_MB"].replace(0, np.nan)
    ).fillna(0)
    mem_feat = last_mem[["timestamp","mem_usage"]]

    # IO 特征（取最新时间戳的所有设备聚合，过滤 loop/sr）
    df_io = df_io[~df_io["device"].astype(str).str.startswith(("loop","sr"))]
    last_ts_io = ts_io
    last_io_slice = df_io[df_io["timestamp"] == last_ts_io]
    io_sum = {
        "timestamp": last_ts_io,
        "io_tps": float(last_io_slice["tps"].fillna(0).sum()),
        "io_read": float(last_io_slice["kB_read_s"].fillna(0).sum()),
        "io_write": float(last_io_slice["kB_wrtn_s"].fillna(0).sum()),
    }
    io_feat = pd.DataFrame([io_sum])

    # NET 特征（选择网卡）
    last_ts_net = ts_net
    net_slice = df_net[df_net["timestamp"] == last_ts_net]
    if PREFERRED_IFACE:
        net_slice = net_slice[net_slice["iface"] == PREFERRED_IFACE]
    else:
        net_slice = net_slice[net_slice["iface"] != "lo"]
        if not net_slice.empty:
            primary_iface = (
                net_slice.set_index("iface")[ ["rx_bytes_s","tx_bytes_s"] ].sum(axis=1).idxmax()
            )
            net_slice = net_slice[net_slice["iface"] == primary_iface]
    if net_slice.empty:
        net_row = {"timestamp": last_ts_net, "net_in": 0.0, "net_out": 0.0}
    else:
        r = net_slice.tail(1).iloc[0]
        net_row = {"timestamp": r["timestamp"], "net_in": float(r["rx_bytes_s"]), "net_out": float(r["tx_bytes_s"])}
    net_feat = pd.DataFrame([net_row])

    # 合并（按最“新的共同时间”对齐）
    ts = min(
        cpu_feat["timestamp"].max(),
        mem_feat["timestamp"].max(),
        io_feat["timestamp"].max(),
        net_feat["timestamp"].max(),
    )
    cpu_feat = cpu_feat[cpu_feat["timestamp"] <= ts].tail(1)
    mem_feat = mem_feat[mem_feat["timestamp"] <= ts].tail(1)
    io_feat  = io_feat[io_feat["timestamp"] <= ts].tail(1)
    net_feat = net_feat[net_feat["timestamp"] <= ts].tail(1)

    df = cpu_feat.merge(mem_feat, on="timestamp", how="inner")
    df = df.merge(io_feat, on="timestamp", how="inner")
    df = df.merge(net_feat, on="timestamp", how="inner")
    return df


def ensure_output_header(path: Path):
    if not path.exists():
        cols = ["timestamp"] + all_features + ["anomaly","status","abnormal_dims"]
        pd.DataFrame(columns=cols).to_csv(path, index=False)


def ensure_features_seed_header(path: Path):
    if not path.exists():
        cols = ["timestamp"] + all_features
        pd.DataFrame(columns=cols).to_csv(path, index=False)


def trigger_bpf(dimensions: list, ts: pd.Timestamp):
    if not dimensions:
        return
    msg = ",".join(dimensions)
    try:
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
        sock.sendto(msg.encode(), SOCKET_PATH.encode())
        sock.close()
        print(f"[{ts}] 已通知用户态: {msg}")
    except Exception as e:
        print(f"Socket 通信失败: {e}")

# 新增：发送控制指令（如 NET_OFF）
def send_control(msg: str, ts: pd.Timestamp):
    try:
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
        sock.sendto(msg.encode(), SOCKET_PATH.encode())
        sock.close()
        print(f"[{ts}] 已通知用户态: {msg}")
    except Exception as e:
        print(f"Socket 通信失败: {e}")

# === 维度判定：基于 z 分数 ===
def _compute_group_max_abs_z(z_values: np.ndarray) -> dict:
    """返回每个维度的最大绝对 z 值。z_values 为与 all_features 对齐的一维数组。"""
    feature_to_index = {name: idx for idx, name in enumerate(all_features)}
    group_to_features = {
        "CPU": cpu_features,
        "MEM": mem_features,
        "IO": io_features,
        "NET": net_features,
    }
    group_to_max_abs_z = {}
    for group_name, feature_names in group_to_features.items():
        indices = [feature_to_index[f] for f in feature_names]
        if not indices:
            group_to_max_abs_z[group_name] = 0.0
            continue
        max_abs = float(np.max(np.abs(z_values[indices])))
        group_to_max_abs_z[group_name] = max_abs
    return group_to_max_abs_z


def _select_abnormal_dimensions(z_values: np.ndarray, dim_z_threshold: float, dim_topk: int) -> list:
    """根据阈值选择异常维度；若都未达阈值，则按最大 |z| 取前 K 个。"""
    group_max = _compute_group_max_abs_z(z_values)
    dims = [g for g, v in group_max.items() if v >= dim_z_threshold]
    if dims:
        return dims
    # 回退：Top-K
    sorted_groups = sorted(group_max.items(), key=lambda x: x[1], reverse=True)
    return [g for g, _ in sorted_groups[:max(1, dim_topk)]]


# === 初始化模型（从种子特征表训练） ===
if FEATURES_SEED.exists():
    seed_df = pd.read_csv(FEATURES_SEED)
else:
    # 回退：从当前数据构建全量特征作为种子
    seed_df = build_features_from_full()

X_seed = seed_df[all_features].fillna(0)
scaler = StandardScaler()
X_scaled = scaler.fit_transform(X_seed)
model = IsolationForest(contamination=CONTAMINATION, random_state=42)
model.fit(X_scaled)
print("✅ 实时监控已启动：模型已训练，开始流式检测...")

# 跟踪 NET 打印开关状态与正常计数
net_print_on = False
normal_streak = 0

# === 主循环：每秒读取最新一行，做检测 & 触发 eBPF ===
ensure_output_header(OUTPUT_FILE)
ensure_features_seed_header(FEATURES_SEED)

while True:
    try:
        df_latest = build_features_latest_row()
        if df_latest.empty:
            time.sleep(0.3)  # 减少等待时间，加速检测
            continue

        ts = df_latest.iloc[0]["timestamp"]
        features_row = df_latest[all_features].fillna(0)
        X_cur = scaler.transform(features_row)
        z_values = X_cur[0]

        # 模型判定 + z 阈值兜底（任一特征 |z| 超阈值则视为异常）
        y_pred_model = model.predict(X_cur)[0]  # -1 异常, 1 正常
        z_based_anomaly = bool(np.any(np.abs(z_values) >= DIM_Z_THRESHOLD))
        y_pred_final = -1 if (y_pred_model == -1 or z_based_anomaly) else 1
        status = "异常" if y_pred_final == -1 else "正常"

        # 仅在异常时按 z 值计算维度并触发 eBPF
        dims = []
        if y_pred_final == -1:
            dims = _select_abnormal_dimensions(z_values, DIM_Z_THRESHOLD, DIM_TOPK)
            # 基于真实阈值过滤 NET（避免 Top-K 回退误触发网络打印）
            group_max = _compute_group_max_abs_z(z_values)
            dims_to_trigger = [d for d in dims if (d != "NET" or group_max.get("NET", 0.0) >= DIM_Z_THRESHOLD)]
            if dims_to_trigger:
                trigger_bpf(dims_to_trigger, ts)
            # 若本次异常包含真实 NET 异常，则标记 NET 打印已开启并清零正常计数
            if "NET" in dims_to_trigger:
                net_print_on = True
                normal_streak = 0
        else:
            # 正常：若之前开启过 NET 打印，则累计正常计数，达到阈值后发送 NET_OFF
            if net_print_on:
                normal_streak += 1
                if normal_streak >= NET_OFF_AFTER_NORMAL:
                    send_control("NET_OFF", ts)
                    net_print_on = False
                    normal_streak = 0

        if y_pred_final == -1:
            dims_str = ",".join(dims_to_trigger) if 'dims_to_trigger' in locals() and dims_to_trigger else ""
            # 若网络打印处于开启状态且未包含 NET，则为对齐终端打印追加 NET 维度
            if net_print_on and (not dims_str or "NET" not in dims_str.split(",")):
                dims_str = (dims_str + ",NET") if dims_str else "NET"
        else:
            dims_str = "正常"

        # 结果落盘（追加）
        out_row = {
            "timestamp": ts,
            **{k: float(df_latest.iloc[0][k]) for k in all_features},
            "anomaly": int(y_pred_final),
            "status": status,
            "abnormal_dims": dims_str,
        }
        pd.DataFrame([out_row]).to_csv(OUTPUT_FILE, mode='a', header=False, index=False)

        # 同步追加特征到种子文件，便于实时查看/累计
        seed_row = {
            "timestamp": ts,
            **{k: float(df_latest.iloc[0][k]) for k in all_features},
        }
        pd.DataFrame([seed_row]).to_csv(FEATURES_SEED, mode='a', header=False, index=False)

        print(f"[{ts}] 状态:{status}{(':' + dims_str) if (y_pred_final == -1 and dims_str) else ''} 特征:{[round(out_row[k],2) for k in all_features]}")

    except Exception as e:
        print("实时监控异常:", e)

    time.sleep(0.2)  # 进一步减少到0.2秒，加速异常检测 