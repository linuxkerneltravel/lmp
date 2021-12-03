#!/usr/bin/env python3
# -*- coding:utf-8 -*-

from influxdb import InfluxDBClient
from config import cfg
from elasticsearch import Elasticsearch

DBNAME = cfg["influxdb"]["dbname"]
USER = cfg["influxdb"]["user"]
PASSWORD = cfg["influxdb"]["password"]

influx_client = InfluxDBClient(database=DBNAME,host='localhost',username=USER,password=PASSWORD)

# TODO: 接入其他数据库
# mysql_client
# es_client
es_client = Elasticsearch(['127.0.0.1:9200'])  # 连接本地9200端口
# prometheus_client
