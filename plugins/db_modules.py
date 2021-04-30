#! /usr/bin/python3
# -*- coding:utf-8 -*-
from const import DatabaseType
from influxdb import InfluxDBClient


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
        pass
    elif dbtype == DatabaseType.MYSQL.value:
        pass
    elif dbtype == DatabaseType.PROMETHEUS.value:
        pass
