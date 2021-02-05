#!/usr/bin/python3
#-*- coding:utf-8 -*-

from influxdb import InfluxDBClient

def connect(dbname,ip='localhost',port=8086,user='admin',passwd='admin'):	
    return InfluxDBClient(ip,port,user,passwd,dbname)
