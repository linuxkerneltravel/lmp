#!/bin/bash
cp ../headers/kprobe.c .
echo go generate
go generate
rm kprobe.c
echo go run .
sudo go run .