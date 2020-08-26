# LMP influxdb template



influxdb的配置文件和数据文件全部存放在lmp/test//influxdb_config：

```bash
.
├── data
├── default.conf
├── meta
└── wal

3 directories, 1 file

```



启动influxdb

```bash
docker run -d \
-p 8083:8083 \
-p 8086:8086 \
--name influxdb \
-v ${YOUR_PATH}/lmp/test/influxdb_config/default.conf:/etc/influxdb/influxdb.conf \
-v ${YOUR_PATH}/lmp/test/influxdb_config/data:/var/lib/influxdb/data \
-v ${YOUR_PATH}/lmp/test/influxdb_config/meta:/var/lib/influxdb/meta \
-v ${YOUR_PATH}/lmp/test/influxdb_config/wal:/var/lib/influxdb/wal influxdb
```



进入influxdb：

```bash
root@741028491d81:/# influx -username root -password ''
password: 
Connected to http://localhost:8086 version 1.8.0
InfluxDB shell version: 1.8.0

```

LMP为influxdb默认建立好了两个管理员用户：

```bash
> show users
user  admin
----  -----
root  true
admin true
```

两个用户的密码都是`123456`，LMP默认使用8086端口来写入数据，除非特别要求，不必设置写入端口。



默认创建好了一个database，其中又创建了三个measurements：

```
name: measurements
name
----
lmp
lmpdata
test
```





## 模板的使用

首先，模板存放于lmp/plugins目录下：

```bash
.
├── api.py
├── db_modules.py
├── db_modules.pyc
├── lmp_influxdb.py
├── lmp_influxdb.pyc
├── runqlen.c
└── waitingqueuelength.py

0 directories, 7 files
```

前5个文件都是模板文件，里面为大家封装了一些操作influxdb的方法，也为大家提供了一个test1.py，是一个最简单的例程用来向influxdb插入数据的，这个test1.py文件位于 `lmp/test/influxdb_test` 目录下；

目前插件只有waitingqueuelength.py和runqlen.c，其余的文件在LMP的插件注册中会忽略掉。

具体使用见`test1.py`和`waitingqueuelength.py`

（第一版比较粗糙）







