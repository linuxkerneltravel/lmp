#!/bin/bash
filecache_dir=model/data_collector/dao/tables
  if [ ! -d $filecache_dir ]; then
	mkdir -p $filecache_dir
	fi
	cd $filecache_dir
	touch ebpfplugin.db