#!/usr/bin/env python3
# -*- coding:utf-8 -*-
from const import DatabaseType
from influxdb import InfluxDBClient
from elasticsearch import Elasticsearch
from db_writer.bufferImpl import Buffer, SingleBuffer
from db_writer.writerImpl import writer_factory

__all__ = ['write2db', 'write2db01', 'write2db02']


def write2db(datatype, data, client, dbtype):
    """
    :param datatype: 数据类型
    :param data: 数`据
    :param client: 数据库client
    :param dbtype: 数据库类型
    """
    if dbtype == DatabaseType.INFLUXDB.value:
        tmp = [{"measurement": None, "tags": {}, "fields": {}, }]
        tmp[0]["measurement"] = datatype["measurement"]
        for x in datatype['tags']:
            tmp[0]["tags"][x] = getattr(data, x)
        for y in datatype['fields']:
            tmp[0]["fields"][y] = getattr(data, y)
        client.write_points(tmp)
    elif dbtype == DatabaseType.ES.value:
        tmp = {"index": None, 'date': {}, }
        tmp["index"] = datatype["measurement"]
        for x in datatype['tags']:
            tmp["date"][x] = getattr(data, x)
        for y in datatype['fields']:
            tmp["date"][y] = getattr(data, y)
        result = client.index(index='lmp', doc_type='performance', body=tmp)
        print(result)
    elif dbtype == DatabaseType.MYSQL.value:
        pass
    elif dbtype == DatabaseType.PROMETHEUS.value:
        pass


# 方案一实现
def write2db01(datatype, data, client=InfluxDBClient, dbtype=DatabaseType.INFLUXDB.value):
    """
    :param datatype: 数据类型
    :param data: 数据
    :param client: 数据库client
    :param dbtype: 数据库类型
    """
    buffer = Buffer()  # 每次调用都存在一个buffer
    writer = writer_factory(dbtype_=datatype, client_=client, buffer_=buffer)  # bind
    writer.start()  # spawn
    while True:
        try:
            buffer.put(_item_adepter(datatype, data))
        except KeyboardInterrupt:
            exit(15)


# 方案二实现：单例守护写进程
def write2db02(datatype, data, client=InfluxDBClient, dbtype=DatabaseType.INFLUXDB.value):
    """
    :param datatype: 数据类型
    :param data: 数据
    :param client: 数据库client
    :param dbtype: 数据库类型
    """
    buffer = SingleBuffer()  # 每次调用都存在一个buffer
    writer = writer_factory(dbtype_=datatype, client_=client, buffer_=buffer, single=True)  # bind
    writer.start()  # spawn
    while True:
        try:
            buffer.put(_item_adepter(datatype, data))
        except KeyboardInterrupt:
            exit(15)


def _item_adepter(datatype_, data_):
    item = [{"measurement": None, "tags": {}, "fields": {}, }]
    item[0]["measurement"] = datatype_["measurement"]
    for x in datatype_['tags']:
        item[0]["tags"][x] = getattr(data_, x)
    for y in datatype_['fields']:
        item[0]["fields"][y] = getattr(data_, y)
    return item
