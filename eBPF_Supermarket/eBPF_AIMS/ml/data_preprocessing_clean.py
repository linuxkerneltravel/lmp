import pandas as pd

# === 配置你的数据路径（项目相对 + 可用环境变量 AIMS_DATA_DIR 覆盖） ===
from pathlib import Path
import os
PROJECT_ROOT = Path(__file__).resolve().parents[1]
DATA_DIR = Path(os.environ.get("AIMS_DATA_DIR", str(PROJECT_ROOT / "data")))
cpu_file = DATA_DIR / "cpu_metrics.csv"
mem_file = DATA_DIR / "mem_metrics.csv"
io_file  = DATA_DIR / "io_metrics.csv"
net_file = DATA_DIR / "net_metrics.csv"

# === 读取 & 清理函数 ===
def load_csv(path):
    df = pd.read_csv(path, delim_whitespace=True)  # 用空格/Tab 分隔
    df.columns = df.columns.str.strip().str.replace("/", "_")
    df["timestamp"] = pd.to_datetime(df["timestamp"])
    return df

df_cpu = load_csv(cpu_file)
df_mem = load_csv(mem_file)
df_io  = load_csv(io_file)
df_net = load_csv(net_file)

# === CPU 特征 ===
df_cpu["cpu_usage"] = df_cpu["us"] + df_cpu["sy"]   # 用户+系统
df_cpu["cpu_wait"]  = df_cpu["wa"]

cpu_feat = df_cpu[["timestamp", "cpu_usage", "cpu_wait"]]

# === MEM 特征 ===
df_mem["mem_usage"] = df_mem["used_MB"] / df_mem["total_MB"]
mem_feat = df_mem[["timestamp", "mem_usage"]]

# === IO 特征 === (过滤掉 loop 和 sr0)
df_io = df_io[~df_io["device"].str.startswith(("loop", "sr"))]
io_agg = (
    df_io.groupby("timestamp")
    .agg({"tps":"sum", "kB_read_s":"sum", "kB_wrtn_s":"sum"})
    .reset_index()
)
io_feat = io_agg.rename(columns={
    "tps": "io_tps", "kB_read_s": "io_read", "kB_wrtn_s": "io_write"
})

# === NET 特征 === (选择主要网卡，优先使用环境变量 AIMS_NET_IFACE)
preferred_iface = os.environ.get("AIMS_NET_IFACE")
if preferred_iface:
    df_net = df_net[df_net["iface"] == preferred_iface]
else:
    df_net = df_net[df_net["iface"] != "lo"]
    if not df_net.empty:
        traffic_by_iface = (
            df_net.groupby("iface")[["rx_bytes_s", "tx_bytes_s"]]
            .sum()
            .sum(axis=1)
        )
        primary_iface = traffic_by_iface.idxmax()
        df_net = df_net[df_net["iface"] == primary_iface]
net_feat = df_net[["timestamp","rx_bytes_s","tx_bytes_s"]].rename(
    columns={"rx_bytes_s":"net_in", "tx_bytes_s":"net_out"}
)

# === 合并 ===
df = cpu_feat.merge(mem_feat, on="timestamp", how="inner")
df = df.merge(io_feat, on="timestamp", how="inner")
df = df.merge(net_feat, on="timestamp", how="inner")

# === 保存 ===
OUTPUT_PATH = PROJECT_ROOT / "ml" / "metrics_features.csv"
df.to_csv(OUTPUT_PATH, index=False)
print("✅ 已生成特征表 metrics_features.csv ->", OUTPUT_PATH)
print(df.head(10))
