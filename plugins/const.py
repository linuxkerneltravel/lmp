from enum import IntEnum

class DatabaseType(IntEnum):
    INFLUXDB = 1
    ES = 2
    MYSQL = 3
    PROMETHEUS = 4
