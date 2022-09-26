# -*- coding: UTF-8 -*-
'''
@Project    : ContXRay
@File       : gen_seccomp.py
@Author     : BAI YUXUAN / DONG XU / ZHANG FAN
@Description: Generate seccomp profile
@Date       : 2022/8/15
'''
import sys
import json

docker_profile = {"defaultAction":"SCMP_ACT_ERRNO","defaultErrnoRet":1,"syscalls":[{"names":[],"action":"SCMP_ACT_ALLOW"}]}
syscall_list = []

if(len(sys.argv) < 3):
    print("Please input the container name and syscall file")
    print("python3 ./gen_seccomp.py container_name file1 file2 ... fileN")
    print("for example: ./gen_seccomp.py ubuntu ./logs/syscall/syscall_1660567876.json")
    sys.exit(1)

cont_name = sys.argv[1]

for i in range(2,len(sys.argv)):
    try:
        file = open(sys.argv[i])
    except:
        print("failed to open %s"%(sys.argv[i]))
        continue
    try:
        table = json.load(file)
        file.close()
    except:
        print("failed to load json str from file %s"%(sys.argv[i]))
        file.close()
        continue
    for k,v in table.items():
        if cont_name in k:
            print(v)
            for v_k in v.keys():
                if v_k not in syscall_list:
                    syscall_list.append(v_k)
        

docker_profile['syscalls'][0]['names'] = syscall_list

filename = "./%s_profile.json"%cont_name
output = open(filename,"w+")
json.dump(docker_profile,output)
output.close()

print("The profile has written to : %s"%filename)
