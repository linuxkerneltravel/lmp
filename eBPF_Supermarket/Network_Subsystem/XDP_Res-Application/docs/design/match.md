## 根据五元组信息匹配对应规则

五元组信息定义：

```c
struct metainfo{
   u32 ipproto; //协议
   u32 saddr; //源ip地址
   u32 daddr; //目的ip地址
   u16 sport; //源端口号
   u16 dport; //目的端口号
};
```

BPF HASH定义（BCC）

```c
BPF_HASH(ipproto_map, u32, u32);
BPF_HASH(saddr_map, u32, u32);
BPF_HASH(daddr_map, u32, u32);
BPF_HASH(sport_map, u16, u32);
BPF_HASH(dport_map, u16, u32);
BPF_HASH(action_map,u32, u32);
```

### 规则预处理

#### 输入

`[IPPROTO,SADDR,DADDR,SPORT,DPORT,ACTION]`

- 对所有ICMP协议的数据包执行DROP

  `[“ICMP”,0,0,0,0,”DROP”]`

- 对所有TCP协议且目的端口号为22的数据包执行DROP

  `[“TCP”,0,0,0,22,”DROP”]`

#### step 1 规范化处理

- 字符串转换为数字，如”ICMP”转为1，”TCP”转为6（`IPPROTO_ICMP`=1,`IPPROTO_TCP`=6）。”DROP”转为1（`XDP_DROP` = 1）

- 源/目的 ip地址/端口号 从主机字节序转换为网络字节序(`htonl`、`htons`)

#### step 2 合并同类型

- 创建一个hash表，如：
```python
rules_merged = {"ipproto":{},"saddr":{},"daddr":{},"sport":{},"dport":{},"action":{}}
```
- 遍历step 1处理后的每条规则，对规则中的每一项，如`dport`，检查`rules_merged`中是否存在以规则中的`dport`的值对应的key。

  若存在，则用该key对应的值与当前规则编号进行**位或(|)**操作。若不存在，则创建一个item，值为当前规则的编号。

- 如果当前项为`0`，如`sport`为`0`，则把key设置为65535

- 每遍历一次，规则编号左移一位。（`i = i << 1`）

### 匹配

- 得到五元组信息后，逐个查找对应map。

- 对结果进行**位与(&)**操作。

- 取出优先级最高的规则（编号小的规则）

  ```c
  result_bit &= -result_bit; // (result_bit &= ~result_bit+1)
  ```

- 格局规则编号，从`action_map`中找到对应规则

  - 若为DROP，则返回`XDP_DROP`
  - 若为REDIRECT，则进行下一步处理
    - 根据规则编号，查找`redirect_map`
    - 修改数据包（包括源/目标 地址/端口），返回`XDP_PASS`继续交给协议栈处理，或者使用`bpf_redirect`返回`XDP_REDIRECT`转发给指定网卡。

### 参考

https://blog.csdn.net/ByteDanceTech/article/details/106632252