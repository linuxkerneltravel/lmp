---
title: LMP 安装部署
description : "介绍 LMP 的基本安装和中间会出现的一些问题。"
weight: 15
---

## LMP 安装部署

### **1.** 拉取项目

```
#git clone https://github.com/linuxkerneltravel/lmp
```

总是有问题

可以用git方式：

```
#git clone git://github.com/linuxkerneltravel/lmp
```

![image-20211210165555598](../images/6.1.png)

上面是从 gitee 中拉下来的，下面是使用git方式拉下来的，都是94M

(110M是因为make之后查看的)

```
root@ubuntu:~# service mysql.server start

root@ubuntu:~# service mysql start

root@ubuntu:~# cd /lmp

root@ubuntu:/lmp# make db

mysql -u root -p <./misc/init.sql

Enter password: 123456

root@ubuntu:/lmp# make
```

报错

go build -mod=vendor -o lmp main.go

vendor/github.com/go-playground/validator/v10/baked_in.go:20:2: cannot find package "." in:

​	/lmp/vendor/golang.org/x/crypto/sha3

Makefile:12: recipe for target 'all' failed

make: *** [all] Error 1

![image-20211210165606107](../images/6.2.png)

```
root@ubuntu:/lmp# go mod tidy

root@ubuntu:/lmp# go mod vendor
```

之后make就可以通过了

### **2.** 运行grafana

```
\# docker run -d \ 

-p 3000:3000 \ 

--name=grafana \ 

grafana/grafana
```

![image-20211210165617125](../images/6.3.png)

### **3.** 运行influxdb

```
\# docker run -d \

-p 8083:8083 \

-p 8086:8086 \

--name influxdb \

-v /lmp/test/influxdb_config/default.conf:/etc/influxdb/influxdb.conf \

-v /lmp/test/influxdb_config/data:/var/lib/influxdb/data \

-v /lmp/test/influxdb_config/meta:/var/lib/influxdb/meta \

-v /lmp/test/influxdb_config/wal:/var/lib/influxdb/wal influxdb:1.8
```

![image-20211210165641124](../images/6.4.png)

**查看是否正常启动：**

root@ubuntu:/lmp# docker ps -a

![image-20211210165648714](../images/7.png)

### **4.** 运行LMP

```
root@ubuntu:/lmp# make

go build -mod=vendor -o lmp main.go

root@ubuntu:/lmp# ./lmp 
```

![image-20211210165704628](../images/8.png)

### **5.** 防火墙

```
root@ubuntu:~# firewall-cmd --zone=public --add-port=8080/tcp --permanent

success

root@ubuntu:~# ufw allow 8080

Rules updated

Rules updated (v6)

root@ubuntu:~# firewall-cmd --reload

success

root@ubuntu:~# firewall-cmd --list-ports

3306/tcp 8080/tcp
```

### **6.** 数据库配置

这里的配置必须在虚拟机中配：

127.0.0.1:3000 用户:admin 密码:admin

-> skip-> DATA SOURCES-> 数据库influxdb

![](../images/9.png)

### **7.** 导入json并观测

/lmp/test/grafana-JSON下的lmp.json文件：

![image-20211210165724383](../images/10.png)

![image-20211210165732011](../images/11.png)

![image-20211210165744712](../images/11.1.png)

完成！！！

## 一些安装时的错误问题

![image-20211210165756267](../images/12.png)

### 报错：ModuleNotFoundError: No module named 'influxdb'

使用：

```
root@ubuntu:/lmp# pip3 install influxdb
```

重新 submit

### 报错：AttributeError: module 'yaml' has no attribute 'FullLoader'

原因：已存在pyyaml，且版本低于5.1

![image-20211210165819604](../images/13.png)

暴力忽视错误升级：

```
\# pip3 install --ignore-installed PyYAML
```

![](../images/14.png)

![image-20211210165833166](../images/15.png)


### 报错：ModuleNotFoundError: No module named 'elasticsearch'

```
root@ubuntu:/lmp# pip3 install elasticsearch
```

### 报错：ModuleNotFoundError: No module named 'db_writer_utils'

```
root@ubuntu:/lmp/plugins/db_writer# vim bufferImpl.py
```

![image-20211210165841378](../images/16.png)

### 报错：FileNotFoundError: [Errno 2] No such file or directory: '/lmp/log/wlog.log'

直接 touch 一个即可。

### 报错：ModuleNotFoundError: No module named 'settings'

打开writerImpl.py

const那句去掉settings：

from const import DatabaseType

添加

import sys

sys.path.append('/lmp/plugins/db_writer')

成功！！！

![image-20211210165856361](../images/17.png)
