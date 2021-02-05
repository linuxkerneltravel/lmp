#!/usr/bin/python3
#-*- coding:utf-8 -*-

from influxdb import InfluxDBClient

def connect(dbname,ip,port,user,passwd):
    return InfluxDBClient(ip,port,user,passwd,dbname)
