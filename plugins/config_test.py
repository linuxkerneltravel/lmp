#!/usr/bin/env python3
# -*- coding:utf-8 -*-
import unittest
from config import cfg


class TestConfig(unittest.TestCase):
    def test_read_config(self):
        self.assertEqual(cfg["influxdb"]["user"], "root")
        self.assertEqual(cfg["influxdb"]["password"], "123456")
        self.assertEqual(cfg["influxdb"]["dbname"], "lmp")


if __name__ == '__main__':
    unittest.main(verbosity=1)
