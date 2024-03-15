# -*- coding: UTF-8 -*-
'''
@Project    : NetCount
@File       : NetCount.py
@Author     : wyn
@Description: Promethus expoter API
@Date       : 2024/2/1
'''
from prometheus_client import start_http_server,Gauge
from time import sleep
import json
import sys
import re

#start_http_server          在指定的端口上启动一个HTTP服务器，以便于让Prometheus 服务器采集指标数据
#Gauge                      表示测量值的实时状态
#sleep                      表示让程序在执行过程中暂停一会
#sys                        包含Python解释器和系统交互的函数
#Gauge                      任意上下波动数值的指标类型，可增可减

#采集指标
sock = Gauge('sock','The amount of sock',['container'])
seq = Gauge('seq','The amount of seq',['container'])
ack = Gauge('ack','The amount of ack',['container'])
mac_time = Gauge('mac_time','The amount of mac_time',['container'])
ip_time = Gauge('ip_time','The amount of ip_time',['container'])
tran_time = Gauge('tran_time','The amount of tran_time',['container'])
http_info = Gauge('http_info','The amount of http_info',['container'])
rx = Gauge('rx','The amount of rx',['container'])

#检查是否成功打开文件
def checkRUNNING():
  try:
    with open("./data/packets.log") as connects_file:
            content = connects_file.read()
  except:
    print("failed to open ./data/packets.log, please check if the NetCount is running!")
    #退出
    sys.exit(1)

def update():
  #打开文件
  with open("./data/packets.log") as connects_file:
    #读取
    # content = connects_file.read()
  #使用正则表达式匹配大括号内的内容
    for line in connects_file:
      match = re.search(r'{([^}]*)}', line)
      if match:
        result = match.group(1)
      else:
        match = None
  # 使用split()函数将字符串分割成键值对，得到kv_pairs列表
      kv_pairs = result.split(',')
      result_dict = {}
      for kv in kv_pairs:
        key, value = kv.split('=')
        value = value.replace('"', '')  # 去掉双引号
        result_dict[key.strip()] = value.strip()
      print(result_dict)
  
  #更新指标值
      for k,v in result_dict.items():
        checkRUNNING()
        if k=='sock':
          sock.labels(container="test").set(len(v))
        elif k=='seq':
          seq.labels(container="test").set(len(v))
        elif k=='ack':
          ack.labels(container="test").set(len(v))
        elif k=='mac_time':
          mac_time.labels(container="test").set(len(v))
        elif k=='ip_time':
          ip_time.labels(container="test").set(len(v))
        elif k=='tran_time':
          tran_time.labels(container="test").set(len(v))
        elif k=='http_info':
          http_info.labels(container="test").set(len(v))
        elif k=='rx':
          rx.labels(container="test").set(len(v))

if __name__ == "__main__":
  start_http_server(9001)
  while True:
    update()
    sleep(1)