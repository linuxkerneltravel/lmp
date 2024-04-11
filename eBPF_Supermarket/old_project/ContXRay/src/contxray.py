#!/usr/bin/env python3
# -*- coding: UTF-8 -*-
'''
@Project    : ContXRay
@File       : contxray.py
<<<<<<< HEAD:contxray.py
@Author     : barryX / DONG XU
=======
@Author     : BAI YUXUAN / DONG XU / ZHANG FAN
>>>>>>> develop:src/contxray.py
@Description: BPF program loading and data processing
@Date       : 2022/8/15
'''

logo_text="""
   _____            _  __   _______             
  / ____|          | | \ \ / /  __ \            
 | |     ___  _ __ | |_ \ V /| |__) |__ _ _   _ 
 | |    / _ \| '_ \| __| > < |  _  // _` | | | |
 | |___| (_) | | | | |_ / . \| | \ \ (_| | |_| |
  \_____\___/|_| |_|\__/_/ \_\_|  \_\__,_|\__, |
                                           __/ |
                                          |___/ 
"""

from bcc import BPF
from bcc.syscall import syscall_name, syscalls
from time import time,strftime,localtime
from struct import pack
from socket import inet_ntop, ntohs, AF_INET, AF_INET6
from datasave import ebpf_data,get_container_name,cont_table,start_time
import os
import sys
import docker



def sys_print(str):
    time_str = strftime("%H:%M:%S",localtime())
    print("\033[1;31m * [ContXRay]:%s - %s\033[0m"%(time_str,str))

# 判断是否root权限启动
if os.geteuid() != 0:
    sys_print("Please use ROOT to run ContXRay!")
    sys.exit(1)

if(os.path.exists("./RUNNING") == True):
    sys_print('File "./RUNNING" is EXISTED')
    sys_print('Please check if The ContXRay is running or remove this file first!')
    sys.exit(1)

RUNNING_file = open("./RUNNING",'w+')
print(start_time,file = RUNNING_file)
RUNNING_file.close()

# 建立docker 容器id-容器名对照表
client = docker.from_env()
containers = client.containers.list()

for i in containers:
    cont_table[i.id[0:11]] = i.name

# LOGO
print(logo_text)
sys_print("Wating for BPF program loading...")

# 加载BPF程序
b = BPF(src_file='bpf.c')
sys_print("BPF program is loaded")

# 将BPF程序挂载到相应的点
b.attach_kretprobe(event= 'do_filp_open',fn_name='trace_fileopen')
b.attach_kretprobe(event= 'sock_alloc',fn_name='trace_sock_alloc')
b.attach_kprobe(event='__tcp_transmit_skb',fn_name='trace_tcp_visit')
b.attach_kprobe(event='tcp_v4_do_rcv',fn_name='trace_tcp_visted')
b.attach_kprobe(event=b.get_syscall_fnname("execve"),fn_name='syscall__execve')

# 创建保存文件
syscall_datafile = ebpf_data("syscall")
fileopen_datafile = ebpf_data("fileopen")
exec_datafile = ebpf_data("exec")
netvisit_datafile = ebpf_data("netvisit")

#系统调用表
syscall_table = {}

sys_print("Start monitoring... Press Ctrl+C to exit")

# test vist_map
def test_tcp_vist():
    for k,v in b['visit'].items():
        saddr = inet_ntop(AF_INET, pack("I", k.saddr))
        daddr = inet_ntop(AF_INET, pack("I", k.daddr))
        # print(str(saddr))
        # print(str(daddr))
        # print(get_container_name(v.cid.decode()));
        print("test seq:%d" %(k.seq))
        b['visit'].pop(k)

# 处理syscall信息
def get_syscalls():
    for k,v in b['syscalls'].items(): #遍历hash table        
        key = str([k.cid.decode(),get_container_name(k.cid.decode())])
        if key not in syscall_table.keys():
            syscall_table[key] = {}
        if syscall_name(k.argsid).decode() not in syscall_table[key].keys():
            syscall_table[key][syscall_name(k.argsid).decode()] = 0
        syscall_table[key][syscall_name(k.argsid).decode()] += int(v.value)
        syscall_datafile.update_table(syscall_table)
    b['syscalls'].clear() #清空hash table

    #print(json.dumps(syscall_table))
    
# 处理fileopen信息
def fileopen_event(cpu,data,size):
    event = b["fileopen_event"].event(data)
    fileopen_datafile.update(event.cid.decode(),[event.pid,event.comm.decode(),event.filename.decode(),event.fsname.decode(),int(time())])

    sys_print("fileopen:::cid:%s-%s,pid:%d,comm:%s-->fs:%s,filename:%s"%(event.cid.decode(),get_container_name(event.cid.decode()),event.pid,event.comm.decode(),event.fsname.decode(),event.filename.decode()))

def test_event(cpu,data,size):
     event = b["visit_event"].event(data)
     saddr=inet_ntop(AF_INET, pack("I", event.saddr))
     daddr = inet_ntop(AF_INET, pack("I",event.daddr))
    #  print(saddr)
    #  print(daddr)
     print("vist->%d" %(event.seq))

def visted_event(cpu,data,size):
     event = b["visited_event"].event(data)
     saddr=inet_ntop(AF_INET, pack("I", event.saddr))
     daddr = inet_ntop(AF_INET, pack("I",event.daddr))
     print("Dest:%s:%d" %(daddr,event.dport)) 
     print("visted<-test seq:%d" %(event.seq))   

# 处理exec信息
def exec_event(cpu,data,size):
    event = b["exec_event"].event(data)
    exec_datafile.update(event.cid.decode(),[event.pid,event.comm.decode(),event.filename.decode(),event.argv.decode(),int(time())])
    
    sys_print("exec:::cid-%s-%s,pid:%d,comm:%s-->filename:%s,argv:%s"%(event.cid.decode(),get_container_name(event.cid.decode()),event.pid,event.comm.decode(),event.filename.decode(),event.argv.decode()))


def test_cv(cpu,data,size):
    event = b["cv_event"].event(data)
    if(event.scid.decode() != event.dcid.decode()):
        netvisit_datafile.update(event.scid.decode(),[event.sport,event.sccomm.decode(),str([event.dcid.decode(),get_container_name(event.dcid.decode())]),event.dport,event.dccomm.decode()])
        sys_print("net:::scid:%s-%s(port:%d comm:%s)-->dcid-%s-%s(port:%d comm:%s)" %(event.scid.decode(),get_container_name(event.scid.decode()),event.sport,event.sccomm.decode()
        ,event.dcid.decode(),get_container_name(event.dcid.decode()),event.dport,event.dccomm.decode()))



# 设置event对应的回调函数
b["fileopen_event"].open_perf_buffer(fileopen_event)
b["exec_event"].open_perf_buffer(exec_event)
b["cv_event"].open_perf_buffer(test_cv)


# 保存数据
def save_data():
    syscall_datafile.save()
    fileopen_datafile.save()
    exec_datafile.save()
    netvisit_datafile.save()

while 1:
    try:
        b.perf_buffer_poll(timeout=100)
        # test_tcp_vist()
        get_syscalls()
        save_data()
    except KeyboardInterrupt:
        os.remove("./RUNNING")
        sys_print("ContXRay is exited!")
        exit()
    
