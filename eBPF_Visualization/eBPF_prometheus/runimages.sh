#!/bin/bash

# 定义镜像名
prometheus_iamge="prom/prometheus"
grafana_iamge="grafana/grafana-enterprise"

# 使用 docker ps 命令列出所有容器的 ID，过滤出指定镜像的容器
prometheus_info=$(sudo docker ps -a -q --filter "ancestor=$prometheus_iamge")
grafana_info=$(sudo docker ps -a -q --filter "ancestor=$grafana_iamge")

# 检查 Prometheus 容器是否存在
if [ -n "$prometheus_info" ]; then
    # 如果容器存在，获取容器的 ID
    # 即获取存储在 $prometheus_info 变量中的容器 ID 列表的第一个容器 ID，并将其存储到 container_id 变量中
    container_id=$(echo "$prometheus_info" | head -n 1)
    echo "prometheus 容器存在,id为$container_id。启动容器..."
    sudo docker start $container_id
else
    echo "容器不存在,开始创建容器,并启动服务"
    # 启动一个新的 Prometheus 容器，映射主机的端口 9090 到容器的端口 9090，
    # 同时将主机上的 Prometheus 配置文件挂载到容器内，以便配置 Prometheus 服务
    sudo docker run \
        -p 9090:9090 \
        -v ./prom_core/prometheus.yaml:/etc/prometheus/prometheus.yml \
        --name=prometheus prom/prometheus &
fi

if [ -n "$grafana_info" ]; then
    # 如果容器存在，获取容器的 ID
    # 即获取存储在 $grafana_info 变量中的容器 ID 列表的第一个容器 ID，并将其存储到 container_id 变量中
    container_id=$(echo "$grafana_info" | head -n 1)
    echo "grafana 容器存在,id为$container_id。启动容器..."
    sudo docker start $container_id
else
    echo "grafana容器不存在,开始创建容器,并启动服务"
    # 启动一个新的 Grafana Enterprise 容器，映射主机的端口 3000 到容器的端口 3000，并指定容器名称为 "grafana"
    sudo docker run -d -p 3000:3000 --name=grafana grafana/grafana-enterprise &
fi