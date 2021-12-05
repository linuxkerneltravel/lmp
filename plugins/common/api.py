#!/usr/bin/env python3
# -*- coding:utf-8 -*-

# for influxdb
import sys
sys.path.append('./plugins/common/')
from db_modules import write2db
from datetime import datetime
from init_db import influx_client

# 在lmp项目中连接influxdb数据库使用lmp_influxdb模块中的connect()
# 除了数据库名称dbname是必选参数外，其余参数默认设置
#数据地址:localhost; port:8086; user:'admin'; passwd:'admin';

# 下面语句等于InfluxDBClient('localhost',8086,'root','123456','lmp')

# 写入数据库需要使用write2db(datatype,data,client)
# datatype是预先定义的数据格式，主要内容是bpf.c中用来输出数据的数据结构体的字段名
# 按照格式 datatype = {"measurement":"table_name",
#                      "tags":['表头字段a','表头字段b'],
#                      "fields:['数据字段c','数据字段d']}
# data是需要写入的数据内容，目前支持bpf_perf_output输出的events对象
# events对象中包含了bpf.c中定义的data数据结构，字段a,b,c,d
# client是需要写入的数据库client


'''
假设在bpf.c文件中定义了如下的data数据结构
struct data_t{
    int   pid
    char  name[]
    char  data[]
    int   tid
    char  address[]
}
其中，id和name是表头字段，可以用来索引，剩余字段是数据字段
我们要将其写入名为'lmp_data'的表中，可以写出如下的datatype
data_struct = {"measurement":'lmpdata',
                "tags":['id','name'],
                "fields":['data','tid','address']}
'''
# 测试用数据


class lmp_data(object):
    def __init__(self, a, b, c, d, e):
        self.pid = a
        self.name = b
        self.data = c
        self.tid = d
        self.address = e


test_data = lmp_data(31256, 'watchdog', 'male', 0, 'xiyou')

data_struct = {"measurement": 'lmpdata',
               "tags": ['pid', 'name'],
               "fields": ['data', 'tid', 'address']}
# 写入数据库
write2db(data_struct, test_data, influx_client, 1)
# 删除数据
# delete(client,measurement,require='xx')
# 目前只支持按tag名，或者按时间顺序筛选删除，具体写法下
# require="'tag_name'='value'" 或者 require="time>time_stamp"
# 示例，删除时间戳大于1590223086102172994的数据
# delete_db(client,'test',require='time>1590223086102172994')

#result = client.query("select * from test;")
#print("Result: {0}".format(result))
