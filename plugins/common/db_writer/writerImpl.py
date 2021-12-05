#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# 
# @Time    : 2021/8/8 19:29
# @Author  : StLeoX
# @Email   : 1228354389@qq.com
import sys
path=sys.path[0]+"/db_writer"
sys.path.append(path)

import queue
from multiprocessing import Process
from db_writer_utils import Singleton, wlog
from bufferImpl import Buffer
from const import DatabaseType
#from settings.const import DatabaseType
__all__ = ['writer_factory']


class Writer(Process):
    def __init__(self, **kwargs):
        super(Writer, self).__init__(name='writer', daemon=False)
        self.client = None
        self.buffer = None
        self.ready_to_run = False

    def run_init(self, client_, buffer_):
        self.client = client_
        self.buffer = buffer_
        self.ready_to_run = True

    def run(self) -> None:
        # super(Writer, self).run()
        assert self.ready_to_run == True, "ready?"


class WriterInfluxdb(Writer):
    def __init__(self):
        super(WriterInfluxdb, self).__init__()

    def run(self) -> None:
        super(WriterInfluxdb, self).run()
        while True:
            try:
                item_ = self.buffer.get(timeout=5)  # 最多等待秒数，之后抛出Empty异常
                # ! special for influxdb here:
                self.client.write_points(item_)
            except KeyboardInterrupt:
                exit(15)
            except queue.Empty:
                wlog.p_info('timeout')
                exit(14)


class WriterEs(Writer):
    pass


class WriterMysql(Writer):
    pass


class WriterPrometheus(Writer):
    pass


@Singleton
class SingleWriterInfluxdb(WriterInfluxdb):
    def __init__(self):
        super(SingleWriterInfluxdb, self).__init__()
        self.daemon = True  # 覆盖，设置成守护进程 special

    def run(self) -> None:
        super(SingleWriterInfluxdb, self).run()


def writer_factory(dbtype_, client_, buffer_, single=False) -> Writer:
    writer_: Writer = Writer()
    if dbtype_ == DatabaseType.INFLUXDB.value:
        writer_ = WriterInfluxdb()
    elif dbtype_ == DatabaseType.ES.value:
        writer_ = WriterEs()
    elif dbtype_ == DatabaseType.MYSQL.value:
        writer_ = WriterMysql()
    elif dbtype_ == DatabaseType.PROMETHEUS.value:
        writer_ = WriterPrometheus()
    else:
        raise NotImplementedError

    if single:
        if dbtype_ == DatabaseType.INFLUXDB.value:
            writer_ = SingleWriterInfluxdb()
        elif dbtype_ == DatabaseType.ES.value:
            writer_ = Singleton(WriterEs)()  # 匿名类
        elif dbtype_ == DatabaseType.MYSQL.value:
            writer_ = Singleton(WriterMysql)()
        elif dbtype_ == DatabaseType.PROMETHEUS.value:
            writer_ = Singleton(WriterPrometheus)()
        else:
            raise NotImplementedError

    writer_.run_init(client_, buffer_)
    return writer_
