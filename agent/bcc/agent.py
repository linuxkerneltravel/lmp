#!/usr/bin/python
# -*- coding: UTF-8 -*-

from __future__ import print_function
from bcc import BPF, PerfType, PerfSWConfig
import os,time,signal,argparse,json,time
from bcc.utils import printb
from importlib import import_module

import prometheus_client
from prometheus_client import Gauge,start_http_server
from flask import Response,Flask
from prometheus_client.core import CollectorRegistry



# 定义命令行参数
parser = argparse.ArgumentParser(description="bcc pro agent",)

# 定义必须参数cmd
parser.add_argument("cmd", help="please input cmd")

args = parser.parse_args()

#从命令行参数中解析需要执行的bcc文件
cmd = args.cmd
cmd = cmd.split('-')

#查找相应的bcc文件，并将其作为module导入
names = locals()
for i in range(len(cmd)):
    file_name = cmd[i]
    module = file_name + '.' + file_name
    names['m%s'%i] = import_module(module)

#使用FLASK,需要创建REGISTRY
REGISTRY = None
#REGISTRY = CollectorRegistry(auto_describe=False)


#使用bcc文件中新增加的create方法，初始化指标输出相关内容
#将调整后的BPF对象放入list中
b = []
for i in range(len(cmd)):
    names['b%s'%i] = names['m'+str(i)].create(REGISTRY)
    b.append(names.get('b'+str(i)))

'''    
#使用FLask作为websever
#目前有些问题，数据传输正常，但响应时间过长，还不清楚原因
app = Flask(__name__)

@app.route('/metrics')
def res():
    for x in b:
        x.perf_buffer_poll()
    return Response(prometheus_client.generate_latest(REGISTRY),mimetype='text/plain')

if __name__ == "__main__":
    app.run(host = '0.0.0.0',port=8000)
'''
#启动prometheus_client自带的webserver
start_http_server(8000)

#提取指标循环遍历BPF对象，执行每个对象的perf_buffer_poll方法
while 1:
    try:
        for x in b:
            x.perf_buffer_poll()
    except KeyboardInterrupt:
        exit()
