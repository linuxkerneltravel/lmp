
IO：如果未装 fio，先安装：sudo apt-get update && sudo apt-get install -y fio

```
fio --name=aims --filename=/var/tmp/aims_io.bin --size=2G --rw=randwrite --bs=64k --iodepth=32 --numjobs=2 --time_based --runtime=45 --direct=1
```

CPU：

```
sudo apt-get install -y stress-ng && stress-ng --cpu 4 --timeout 45s
```

内存：

```
stress-ng --vm 2 --vm-bytes 80% --timeout 45s
```

网络：

（1）第一种

- 在另一台主机跑 

  ```
  iperf3 -s
  ```

  

- 本机跑

  ```
   iperf3 -c <server> -t 45
  ```

  （2）第二种：或者直接下载大文件，下载完删除

  ```
  wget --no-check-certificate -O /tmp/aims_net_test.bin https://speed.hetzner.de/1GB.bin && rm -f /tmp/aims_net_test.bin
  ```
  （3）
  # 网络负载测试命令集合

## 1. HTTP 请求测试
# 使用 curl 发送大量 HTTP 请求
for i in {1..100}; do curl -s http://httpbin.org/get > /dev/null & done

# 使用 wget 测试
for i in {1..50}; do wget -q -O /dev/null http://httpbin.org/get & done

## 2. TCP 连接测试
# 使用 nc (netcat) 建立多个 TCP 连接
for i in {1..20}; do nc -z google.com 80 & done

# 使用 telnet 测试
for i in {1..10}; do timeout 5 telnet google.com 80 & done

## 3. 网络带宽测试
# 使用 iperf3 (需要安装)
# 服务器端: iperf3 -s
# 客户端: iperf3 -c <server_ip> -t 60

# 使用 dd 和 nc 传输数据
dd if=/dev/zero bs=1M count=100 | nc <target_ip> 8080

## 4. DNS 查询测试
# 大量 DNS 查询
for i in {1..50}; do nslookup google.com & done

## 5. 端口扫描测试
# 使用 nmap 扫描
nmap -p 1-1000 localhost

# 使用 nc 扫描端口
for port in {1..100}; do nc -z localhost  & done

## 6. 持续网络活动
# 持续 ping
ping -c 1000 google.com

# 持续 HTTP 请求
while true; do curl -s http://httpbin.org/get > /dev/null; sleep 0.1; done

## 7. 并发连接测试
# 使用 ab (Apache Bench) 进行压力测试
ab -n 1000 -c 10 http://httpbin.org/get

# 使用 wrk 进行高并发测试
wrk -t12 -c400 -d30s http://httpbin.org/get

## 8. 文件传输测试
# 使用 scp 传输大文件
dd if=/dev/zero of=testfile bs=1M count=100
scp testfile user@remote_host:/tmp/

# 使用 rsync 同步
rsync -avz --progress testfile user@remote_host:/tmp/


  