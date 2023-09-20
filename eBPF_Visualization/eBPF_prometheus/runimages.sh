#!/bin/bash

# 定义镜像名
prometheus_iamge="prom/prometheus"
grafana_iamge="grafana/grafana-enterprise"

prometheus_info=$(docker ps -a -q --filter "ancestor=$prometheus_iamge")
grafana_info=$(docker ps -a -q --filter "ancestor=$grafana_iamge")

if [ -n "$prometheus_info" ]; then
    # 如果容器存在，获取容器的 ID
    container_id=$(echo "$prometheus_info" | head -n 1)
    echo "prometheus 容器存在,id为$container_id。启动容器..."
    sudo docker start $container_id
else
    echo "容器不存在,开始创建容器,并启动服务..."
    sudo docker run \
        -p 9090:9090 \
        -v ./prom_core/promehteus.yaml:/etc/prometheus/prometheus.yml \
        prom/prometheus
fi

if [ -n "$grafana_info" ]; then
    # 如果容器存在，获取容器的 ID
    container_id=$(echo "$grafana_info" | head -n 1)
    echo "grafana 容器存在,id为$container_id。启动容器..."
    sudo docker start $container_id
else
    echo "grafana容器不存在,开始创建容器,并启动服务..."
    sudo docker run -d -p 3000:3000 --name=grafana grafana/grafana-enterprise
fi