#!/bin/python

'''
Copyright 2023 The LMP Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

https://github.com/linuxkerneltravel/lmp/blob/develop/LICENSE

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

author: luiyanbing@foxmail.com

数据直方图分析脚本
'''

import matplotlib.pyplot as plt
from time import time

data = []
with open('stack_count.stk', 'r') as f:
    for line in f:
        line = line.replace('\n','')
        if line.isdigit():
            data.append([int(line)])

from pyod.models.mad import MAD
from pyod.models.pca import PCA
from pyod.models.knn import KNN
from pyod.models.iforest import IForest
clfs = [MAD(), PCA(), KNN(), IForest()]
# clfs = [ECOD()]
for clf in clfs:
    start = time()
    clf.fit(data)
    end = time()
    print(clf.__module__, end-start)
    labels = clf.labels_.astype(int).tolist()
    count = [[],[]]
    for c, l in zip(data, labels):
        if l:
            count[1].append(c[0])
        else:
            count[0].append(c[0])
    plt.figure(figsize=(6,4))
    plt.hist(count, bins=100, label=['normal', 'anomaly'], color=['c','r'])
    plt.ylim([0,10])
    plt.xlabel('Stack Count', fontdict={'family' : 'DejaVu Serif'})
    plt.ylabel('Frequency', fontdict={'family' : 'DejaVu Serif'})
    plt.legend(prop={'family' : 'DejaVu Serif'})
    plt.title(clf.__module__, fontdict={'family' : 'DejaVu Serif'})
    plt.savefig('on-cpu-%s.png'%(clf.__module__))
    plt.close()