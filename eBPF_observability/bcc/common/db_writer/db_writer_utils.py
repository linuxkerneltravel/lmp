#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# 
# @Time    : 2021/8/8 19:47
# @Author  : StLeoX
# @Email   : 1228354389@qq.com

# 单例装饰器
import logging


class Singleton(object):
    def __init__(self, cls):
        self._cls = cls
        self._instance = {}

    def __call__(self,*args,**kwargs):
        if self._cls not in self._instance:
            self._instance[self._cls] = self._cls()
        return self._instance[self._cls]


class WriterLogger(logging.Logger):
    def __init__(self):
        super(WriterLogger, self).__init__(name='wlog')
        # self.setLevel(logging.DEBUG)
        logging.basicConfig(filename=r"./wlog.log",
                            filemode='w',  # 允许覆盖
                            level=logging.DEBUG,  # 允许输出info
                            format="%(asctime)s - %(levelname)s - %(message)s"
                            )

    def p_info(self, msg):
        print(msg)
        logging.info(msg)


wlog = WriterLogger()
