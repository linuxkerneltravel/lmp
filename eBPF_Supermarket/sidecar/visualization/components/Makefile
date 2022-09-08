mkfile_path := $(abspath $(lastword $(MAKEFILE_LIST)))
mkfile_dir := $(dir $(mkfile_path))

local_ip = $(LOCAL_IP)
sidecar_ip = $(SIDECAR_IP)
visualize_ip = $(VISUALIZE_IP)
exit_flag=0

ifeq ($(local_ip),)
$(info LOCAL_IP not set!)
exit_flag=1
endif
ifeq ($(sidecar_ip),)
$(info SIDECAR_IP not set!)
exit_flag=1
endif
ifeq ($(visualize_ip),)
$(info VISUALIZE_IP not set!)
exit_flag=1
endif

ifeq ($(exit_flag),1)
deploy:
pull:
else
deploy: _deploy
pull: _pull
endif

node_exporter_ip = $(sidecar_ip)
node_exporter_port = 9100
cadvisor_ip = $(sidecar_ip)
cadvisor_port = 8080
sidecar_exporter_ip = $(sidecar_ip)
sidecar_exporter_port = 8765

prometheus_ip = $(visualize_ip)
prometheus_port = 9090
pushgateway_ip = $(visualize_ip)
pushgateway_port = 9091
grafana_ip = $(visualize_ip)
grafana_port = 3000
jaeger_ip = $(visualize_ip)
jaeger_port = 6831

_pull:
	@if [ $(sidecar_ip) = $(local_ip) ]; then\
		docker pull prom/node-exporter;\
		docker pull gcr.io/cadvisor/cadvisor;\
	fi

	@if [ $(visualize_ip) = $(local_ip) ]; then\
		docker pull prom/prometheus;\
		docker pull prom/pushgateway;\
		docker pull grafana/grafana;\
	fi

_deploy:
	sed -e "s/prometheus_ip_port/$(prometheus_ip):$(prometheus_port)/g" \
		-e "s/pushgateway_ip_port/$(pushgateway_ip):$(pushgateway_port)/g" \
		-e "s/node_exporter_ip_port/$(node_exporter_ip):$(node_exporter_port)/g" \
		-e "s/cadvisor_ip_port/$(cadvisor_ip):$(cadvisor_port)/g" \
		-e "s/sidecar_exporter_ip_port/$(sidecar_exporter_ip):$(sidecar_exporter_port)/g" \
		prometheus_template.yml > prometheus.yml

	@if [ $(sidecar_ip) = $(local_ip) ]; then\
		docker      run -d --name sidecar-node-exporter	-p $(node_exporter_port):9100 prom/node-exporter;\
		sudo docker run -d --name=sidecar-cadvisor      -p $(cadvisor_port):8080      --volume=/:/rootfs:ro --volume=/var/run:/var/run:ro --volume=/sys:/sys:ro --volume=/var/lib/docker/:/var/lib/docker:ro --volume=/dev/disk/:/dev/disk:ro --detach=true --privileged --device=/dev/kmsg gcr.io/cadvisor/cadvisor;\
		echo "Node exporter at http://$(node_exporter_ip):$(node_exporter_port)/";\
		echo "cAdvisor at http://$(cadvisor_ip):$(cadvisor_port)/";\
	fi

	@if [ $(visualize_ip) = $(local_ip) ]; then\
		docker run -d --name sidecar-prometheus		-p $(prometheus_port):9090 	-v ~/data/prom-data:/prometheus -v $(mkfile_dir)prometheus.yml:/etc/prometheus/prometheus.yml --user root prom/prometheus;\
		docker run -d --name sidecar-pushgateway	-p $(pushgateway_port):9091	-v ~/data/grafana-data:/var/lib/grafana prom/pushgateway;\
		docker run -d --name sidecar-grafana		-p $(grafana_port):3000		grafana/grafana;\
		docker run -d --name sidecar-jaeger 		-p $(jaeger_port):6831/udp  -p 6832:6832/udp -p 5778:5778 -p 16686:16686 -p 4317:4317 -p 4318:4318 -p 14250:14250 -p 14268:14268 -p 14269:14269 -p 9411:9411 -e COLLECTOR_ZIPKIN_HOST_PORT=:9411 -e COLLECTOR_OTLP_ENABLED=true jaegertracing/all-in-one;\
		echo "Prometheus at http://$(prometheus_ip):$(prometheus_port)/";\
		echo "Pushgateway at http://$(pushgateway_ip):$(pushgateway_port)/";\
		echo "Grafana at http://$(grafana_ip):$(grafana_port)/";\
	fi

stop:
	-docker stop sidecar-prometheus
	-docker stop sidecar-pushgateway
	-docker stop sidecar-grafana
	-docker stop sidecar-jaeger
	-docker stop sidecar-node-exporter

start:
	-docker start sidecar-prometheus
	-docker start sidecar-pushgateway
	-docker start sidecar-grafana
	-docker start sidecar-jaeger
	-docker start sidecar-node-exporter
	-docker start sidecar-cadvisor

rm:
	-docker rm sidecar-prometheus
	-docker rm sidecar-pushgateway
	-docker rm sidecar-grafana
	-docker rm sidecar-jaeger
	-docker rm sidecar-node-exporter
	-docker rm sidecar-cadvisor
	rm prometheus.yml
