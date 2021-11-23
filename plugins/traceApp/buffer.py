#!/usr/bin/env python
# coding=utf-8

# 记录名称和pid信息
list = dict()


def add(pid, name):
    list[pid] = name


def delete(pid) -> int:
    if pid in list:
        del list[pid]
        return 1
    else:
        return 0


def travel():
    count = 0
    print("\n %-11s %-7s %s" % ("COUNT", "PID", "NAME"))
    for key, value in list.items():
        count += 1
        print("%-11s %-7d % s" % (count, key, value))

    list.clear()
