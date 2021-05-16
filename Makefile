VERSION = 0.1
.PHONY: all clean modules lint

PREFIX    ?= /usr/libexec/lmp
COLLECTDIR = $(PREFIX)/collector
PRE ?= /opt
PRODIR = $(PRE)/prometheus
GRADIR = $(PRE)/grafana-storage
DASHDIR = $(PRE)/grafana

all:
	go build -mod=vendor -o lmp main.go

db:
	mysql -u root -p <./misc/init.sql

clean:
	rm -rf lmp
	rm -rf lmp.log
	rm -rf lmp.pid
	rm -rf $(PREFIX)
	rm -rf $(PRODIR)
	rm -rf $(GRADIR)
	rm -rf $(DASHDIR)

install:
	@echo "BEGIN INSTALL LMP"
	mkdir -p /etc/influxdb/influxdb.conf
	mkdir -p /var/lib/influxdb/data
	mkdir -p /var/lib/influxdb/meta
	mkdir -p /var/lib/influxdb/wal influxdb
# 	mkdir -p $(COLLECTDIR)
# 	mkdir -p $(PRODIR)
# 	mkdir -p $(GRADIR)
# 	mkdir -p $(DASHDIR)
# 	chmod 777 -R $(GRADIR)
# 	install -m 755 test/bpf/collect.py $(COLLECTDIR)
# 	install -m 640 test/bpf/collect.c $(COLLECTDIR)
# 	install -m 644 test/prometheus/* $(PRODIR)
# 	install -m 640 test/grafana/* $(DASHDIR)

lint:
	go fmt ./...
	go vet ./...
	gofmt -e -l .
	# golint `go list ./... | grep -v /vendor/`
