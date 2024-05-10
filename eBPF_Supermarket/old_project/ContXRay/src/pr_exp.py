# -*- coding: UTF-8 -*-
'''
@Project    : ContXRay
@File       : pr_exp.py
@Author     : barryX / DONG XU
@Description: Promethus expoter API
@Date       : 2022/8/15
'''
from prometheus_client import start_http_server,Gauge
from time import sleep
import json
import sys

syscall = Gauge('syscall','The amount of syscalls',['container'])
exec = Gauge('exec','The amount of exec',['container'])
fileopen = Gauge('fileopen','The amount of fileopen',['container'])
netvisit = Gauge('netvisit','The amount of netvisit',['container'])

'''
syscall_count = {}
exec_count = {}
fileopen_count = {}
netvisit_count = {}
'''

start_time = ""

def checkRUNNING():
  try:
    global start_time
    RUNNING_file = open("./RUNNING","r")
    start_time = RUNNING_file.read()
    start_time = start_time.replace('\n','')
  except:
    print("failed to open ./RUNNING, please check if the ContXRay is running!")
    sys.exit(1)

def update():
  checkRUNNING()
  syscall_file = open("./logs/syscall/syscall_%s.json"%start_time)
  exec_file = open("./logs/exec/exec_%s.json"%start_time)
  fileopen_file = open("./logs/fileopen/fileopen_%s.json"%start_time)
  netvisit_file = open("./logs/netvisit/netvisit_%s.json"%start_time)
  syscall_table = json.load(syscall_file)
  exec_table = json.load(exec_file)
  fileopen_table = json.load(fileopen_file)
  netvisit_table = json.load(netvisit_file)
  syscall_file.close()
  exec_file.close()
  fileopen_file.close()
  netvisit_file.close()
  for k,v in syscall_table.items():
    syscall.labels(container=k).set(len(v.keys()))
  for k,v in exec_table.items():
    exec.labels(container=k).set(len(v))
  for k,v in fileopen_table.items():
    fileopen.labels(container=k).set(len(v))
  for k,v in netvisit_table.items():
    netvisit.labels(container=k).set(len(v))
    


if __name__ == "__main__":
  start_http_server(9001)
  while 1:
    update()
    sleep(1)