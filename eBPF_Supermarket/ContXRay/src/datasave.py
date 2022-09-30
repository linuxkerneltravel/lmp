# -*- coding: UTF-8 -*-
'''
@Project    : ContXRay
@File       : datasave.py
@Author     : barryX / DONG XU
@Description: Data persistence saving
@Date       : 2022/8/15
'''

from time import time
import json

cont_table = {'None':'None'}
start_time = int(time())

# 查表获取容器id对应容器名
def get_container_name(cid):
    try:
        result = cont_table[cid]
    except:
        result = "None"
    return result

# 数据存放类
class ebpf_data:
    def __init__(self,name):
        self.name = name
        self.__json_file_path = "./logs/%s/%s_%d.json"%(name,name,start_time)
        self.__json_file_obj = open(self.__json_file_path,"w")
        self.__table = {}

    # 更新table
    def update(self,cid,data): #data为list
        if(len(cid) == 0):
            cid = 'None'
        key = str([cid,get_container_name(cid)])
        if key not in self.__table.keys():
            self.__table[key] = []
        self.__table[key].append(data)
    
    # 更新table(通过直接传递table)
    def update_table(self,table):
        self.__table = table

    # 获取table
    def get_table(self):
        return self.__table

    # 保存到文件
    def save(self):
        buf = json.dumps(self.__table)
        for i in range(0,self.__json_file_obj.tell() - len(buf)):
            buf = buf + " "
        self.__json_file_obj.seek(0)
        self.__json_file_obj.write(buf)
        self.__json_file_obj.flush()
