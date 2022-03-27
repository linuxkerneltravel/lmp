#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# 
# @Time    : 2021/8/8 19:37
# @Author  : StLeoX
# @Email   : 1228354389@qq.com
import sys
sys.path.append('./plugins/common/db_writer')
from queue import Queue
from db_writer_utils import Singleton


# # 存在参数在这里可以调节
# buffer_queue = Queue()


class Buffer(Queue):
    def __init__(self):
        super(Buffer, self).__init__()


@Singleton
class SingleBuffer(Queue):
    def __init__(self):
        super(SingleBuffer, self).__init__()
