#! /usr/bin/python3
#-*- coding:utf-8 -*-

from influxdb import InfluxDBClient
from datetime import datetime

protocol = 'line'
def write2db(datatype,data,client):
    tmp = [{"measurement":None,"tags":{},"fields":{},"time":datetime.now().isoformat()}]
    tmp[0]["measurement"] = datatype["measurement"]
    for x in datatype['tags']:
        tmp[0]["tags"][x] = getattr(data,x)
    for y in datatype['fields']:
        tmp[0]["fields"][y] = getattr(data,y)
    for z in datatype['time']:
        tmp[0]['time'][z] = getattr(data,z)
    client.write_points(tmp)