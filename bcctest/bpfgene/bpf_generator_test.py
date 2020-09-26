#!/usr/bin/python3
# -*- coding: utf-8 -*-

import os,stat
import json
 
def file_generator():
    
    #接收的json格式的命令，目前是用本地的文件
    with open ('/home/test/bcc_test/local_work/bpfgene/cmd.json','r') as jfd :
          load_json =  json.load(jfd)
 
    key = list(load_json['cmd'])
    #BPF_GENERATOR_arg 基于json文件中的'cmd'对象生成的一段字符串
    BPF_GENERATOR_arg = ''
    for x in key:
        BPF_GENERATOR_arg += load_json['cmd'][x]
        
    #源文件路径，目前是本地的，后期要改为lmp项目的绝对路径
    #subsystem 和 metrics 是文件夹名，存放相应领域的bcc工具脚本
    src_path = os.path.join(os.path.abspath('.'),load_json['subsystem'],load_json['metrics'])
    #目标文件路径，目前是本地，后期应改为lmp项目专用的生成文件路径，文件名应跟请求绑定。
    drc_path = os.path.join(os.path.abspath('.'),'new_py','task1.py')
    print(src_path)
    with open(src_path,'r',encoding = 'utf-8') as sf, open(drc_path,'w',encoding = 'utf-8') as df:
        for line in sf.readlines():
            #'BPF_GENERATOR_args'在源文件中是全局唯一的一个字符串，用于标识替换位置
            #将其替换为基于json文件生成的命令字符串
            if 'BPF_GENERATOR_args' in line:
               line = line.replace('BPF_GENERATOR_args',BPF_GENERATOR_arg)
               
            df.write(line)
   
   #修改生成文件的权限，给予文件拥有者所有权限
    os.chmod(drc_path,stat.S_IRWXU)


if __name__ == '__main__':
    file_generator()
