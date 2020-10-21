#! /usr/bin/python3
#-*- coding:utf-8 -*-
from influxdb import InfluxDBClient
protocol = 'line'
def write2db(datatype,data,client):
    tmp = [{"measurement":None,"tags":{},"fields":{},}] 
    tmp[0]["measurement"] = datatype["measurement"]
    for x in datatype['tags']:
        tmp[0]["tags"][x] = getattr(data,x)
    for y in datatype['fields']:
        tmp[0]["fields"][y] = getattr(data,y)
    client.write_points(tmp)