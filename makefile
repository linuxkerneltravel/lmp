VERSION = 0.1
.PHONY: all clean modules

PREFIX    ?= /usr/libexec/lmp
COLLECTDIR = $(PREFIX)/collector
PRE ?= /opt
PRODIR = $(PRE)/prometheus
GRADIR = $(PRE)/grafana-storage
DASHDIR = $(PRE)/grafana

all:
	# go build -mod=vendor -o cmd/main cmd/main.go
	go build -o cmd/main cmd/main.go

clean:
	rm -rf cmd/main
	rm -rf logs
	rm -rf cmd/main.pid
	rm -rf $(PREFIX)
	rm -rf $(PRODIR)
	rm -rf $(GRADIR)
	rm -rf $(DASHDIR)

install:
	@echo "BEGIN INSTALL LMP"
	mkdir -p $(COLLECTDIR)
	mkdir -p $(PRODIR)
	mkdir -p $(GRADIR)
	mkdir -p $(DASHDIR)
	chmod 777 -R $(GRADIR)
	install -m 755 test/bpf/collect.py $(COLLECTDIR)
	install -m 640 test/bpf/collect.c $(COLLECTDIR)
	install -m 644 test/prometheus/* $(PRODIR)
	install -m 640 test/grafana/* $(DASHDIR)
