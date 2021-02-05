#!/usr/bin/python3
#-*- coding:utf-8 -*-

import config_with_yaml as config

YAML_CONFIG="../config.yaml"

def read_config():
    cfg = config.load(YAML_CONFIG)
    return cfg

cfg = read_config()
# for test
if __name__=='__main__':
    print(cfg.getProperty("influxdb.user"))
    print(cfg.getProperty("influxdb.password"))
    print(cfg.getProperty("influxdb.dbname"))

