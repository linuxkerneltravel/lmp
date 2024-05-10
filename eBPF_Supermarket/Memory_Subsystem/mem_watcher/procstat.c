// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2020 Facebook */
#include <argp.h>
#include <signal.h>
#include <stdio.h>
#include <time.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include "mem_watcher.h"
#include "procstat.skel.h"
#include <sys/select.h>
#include <unistd.h>

int main(int argc, char **argv) {
	
}