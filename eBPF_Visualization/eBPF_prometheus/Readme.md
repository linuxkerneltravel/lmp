## BPF数据可视化

​	该项目是eBPF_Visualization项目的一部分，目前是一个命令行工具，实现数据加载到符合Prometheus规范的metrics中，此后，利用prometheus-server方便地对收集地数据进行管理，利用grafana进行数据的可视化。

## 输出的格式要求

第一行输出各项指标的名称，之后每一行输出数据，以空格分隔。

e.g.

```
TIME         READ/s  WRITE/s  FSYNC/s   OPEN/s CREATE/s
14:15:45:      1119       22        0       42        0
14:15:46:       831       28        0      726        0
```

## 使用方式

```
$ make
$ ./data-visual collect example/vfsstat.py
```

程序会自动将bpf程序的输出收集到metrics中。

通过访问http://127.0.0.1:8090/metrics 可实时查看收集到的metrics。

### 使用prometheus-server的docker镜像监控metrics

编辑prom_core/prometheus.yaml中targets参数，使其符合用户ip地址，默认127.0.0.1。之后使用下述操作。

```bash
docker run \
    -p 9090:9090 \
    -v ./prom_core/promehteus.yaml:/etc/prometheus/prometheus.yml \
    prom/prometheus
```

以上命令会自动下载prometheus-server的docker镜像，并以/prom_core/promehteus.yaml为配置文件启动prometheus-server。

通过访问http://127.0.0.1:9090 可对prometheus-server进行管理。进入Status-Targets,即可看到metrics的状态。
![捕获1](https://github.com/Gui-Yue/lmp/assets/78520005/0ed9e69f-d477-4f7e-91e0-3e9d240f31d3)


### 使用grafana的docker镜像绘图

```bash
docker run -d -p 3000:3000 --name=grafana grafana/grafana-enterprise
```

以上命令会自动下载grafana的docker镜像，并启动，可通过http://127.0.0.1:3000 访问。在grafana中进行可视化设置，选择prometheus服务器，即可实现metrics可视化。效果如下：
![捕获2](https://github.com/Gui-Yue/lmp/assets/78520005/b7bb8668-b3cb-496a-bbfc-ba74ea3ef1b7)

