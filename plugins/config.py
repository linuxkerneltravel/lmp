#!/usr/bin/python3
# -*- coding:utf-8 -*-

import yaml
import os

current_path = os.path.abspath(".")
yaml_path = os.path.join(current_path, "config.yaml")


def read_config():
    with open(yaml_path,'r') as stream:
        cfg =yaml.load(stream,Loader=yaml.FullLoader)
    return cfg

cfg = read_config()
