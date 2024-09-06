import pandas as pd
import matplotlib.pyplot as plt

# 步骤 1: 将 .txt 文件转换为 .csv 文件
input_txt_file = './output.txt'  # 你的 .txt 文件路径
output_csv_file = './data.csv'  # 输出 .csv 文件路径

# 读取 .txt 文件内容并写入 .csv 文件
with open(input_txt_file, 'r') as txt_file:
    lines = txt_file.readlines()

# 写入 .csv 文件
with open(output_csv_file, 'w') as csv_file:
    for line in lines:
        # 替换多余空格为逗号，准备写入到 .csv 文件
        formatted_line = ','.join(line.split())
        csv_file.write(formatted_line + '\n')

# 步骤 2: 读取 .csv 文件并进行数据分析
data = pd.read_csv(output_csv_file, header=None)

# 给列命名，每三个数据为一组，分别对应 lookup、insert、delete 操作
data.columns = ['hash_lookup', 'hash_insert', 'hash_delete',
                'array_lookup', 'array_insert', 'array_delete',
                'percpu_array_lookup', 'percpu_array_insert', 'percpu_array_delete',
                'percpu_hash_lookup', 'percpu_hash_insert', 'percpu_hash_delete']

# 计算每种 map 类型的平均操作时间
avg_hash = data[['hash_lookup', 'hash_insert', 'hash_delete']].mean()
avg_array = data[['array_lookup', 'array_insert', 'array_delete']].mean()
avg_percpu_array = data[['percpu_array_lookup', 'percpu_array_insert', 'percpu_array_delete']].mean()
avg_percpu_hash = data[['percpu_hash_lookup', 'percpu_hash_insert', 'percpu_hash_delete']].mean()

# 创建一个 DataFrame 来存储平均值
avg_table = pd.DataFrame({
    'Operation': ['lookup', 'insert', 'delete'],
    'Hash Map': avg_hash.values,
    'Array Map': avg_array.values,
    'Per-CPU Array': avg_percpu_array.values,
    'Per-CPU Hash': avg_percpu_hash.values
})

# 打印平均值表格到控制台
print("Average Execution Time of eBPF Map Operations (in seconds):\n")
print(avg_table.to_string(index=False))

# 绘制平均操作时间的图表
plt.figure(figsize=(10, 6))

# 绘制四种 map 类型的平均时间曲线
operations = ['lookup', 'insert', 'delete']

plt.plot(operations, avg_hash, marker='o', linestyle='-', color='b', label='Hash')
plt.plot(operations, avg_array, marker='s', linestyle='-', color='r', label='Array')
plt.plot(operations, avg_percpu_array, marker='^', linestyle='-', color='g', label='Per-CPU Array')
plt.plot(operations, avg_percpu_hash, marker='d', linestyle='-', color='purple', label='Per-CPU Hash')

# 图表设置
plt.title('Average Execution Time of eBPF Map Operations')
plt.xlabel('Operation Type')
plt.ylabel('Time (seconds)')
plt.legend(loc='upper left')
plt.grid(True)

# 显示图表
plt.savefig('ebpf_map_operation_times.png')  # 保存图表为文件
plt.show()
