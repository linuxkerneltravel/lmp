import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
import socket
import time

# === 配置文件路径（项目相对 + 环境变量可覆盖） ===
from pathlib import Path
import os
PROJECT_ROOT = Path(__file__).resolve().parents[1]
ML_DIR = PROJECT_ROOT / "ml"
DATA_FILE_ENV = os.environ.get("AIMS_FEATURES_FILE")
data_file = DATA_FILE_ENV if DATA_FILE_ENV else str(ML_DIR / "metrics_features.csv")

# === 读入数据 ===
df = pd.read_csv(data_file)

# === 特征维度 ===
cpu_features = ["cpu_usage","cpu_wait"]
mem_features = ["mem_usage"]
io_features  = ["io_tps","io_read","io_write"]
net_features = ["net_in","net_out"]

all_features = cpu_features + mem_features + io_features + net_features
X = df[all_features].fillna(0)

# === 标准化 ===
scaler = StandardScaler()
X_scaled = scaler.fit_transform(X)

# === Isolation Forest 异常检测 ===
model = IsolationForest(contamination=0.05, random_state=42)
df["anomaly"] = model.fit_predict(X_scaled)  # -1 = 异常, 1 = 正常

# === Socket 设置 ===
SOCKET_PATH = os.environ.get("AIMS_SOCKET_PATH", "/tmp/bpf_trigger.sock")

def trigger_bpf(row):
    abnormal_dims = []
    if any(row[f] != 0 for f in cpu_features):
        abnormal_dims.append("CPU")
    if any(row[f] != 0 for f in mem_features):
        abnormal_dims.append("MEM")
    if any(row[f] != 0 for f in io_features):
        abnormal_dims.append("IO")
    if any(row[f] != 0 for f in net_features):
        abnormal_dims.append("NET")

    # 如果有异常，就发消息给 libbpf 用户态
    if abnormal_dims:
        msg = ",".join(abnormal_dims)
        try:
            sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
            sock.sendto(msg.encode(), SOCKET_PATH.encode())
            sock.close()
            print(f"[{row['timestamp']}] 已通知用户态: {msg}")
        except Exception as e:
            print(f"Socket 通信失败: {e}")
        return msg
    else:
        return "正常"

# === 遍历异常点触发 hook 并记录异常维度 ===
abnormal_list = []
for _, row in df.iterrows():
    if row["anomaly"] == -1:
        dims = trigger_bpf(row)
        abnormal_list.append(dims)
        time.sleep(0.5)  # 防止短时间内过载
    else:
        abnormal_list.append("正常")

df["status"] = df["anomaly"].apply(lambda x: "异常" if x==-1 else "正常")
df["abnormal_dims"] = abnormal_list

# === 保存检测结果 ===
OUTPUT_FILE_ENV = os.environ.get("AIMS_OUTPUT_FILE")
output_file = OUTPUT_FILE_ENV if OUTPUT_FILE_ENV else str(ML_DIR / "metrics_with_bpf.csv")
df.to_csv(output_file, index=False)
print("✅ 异常检测+Socket通知完成，结果已保存到", output_file)
