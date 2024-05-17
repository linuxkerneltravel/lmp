/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/* Copyright (c) 2020 Facebook */
#ifndef __BOOTSTRAP_H
#define __BOOTSTRAP_H

#define TASK_COMM_LEN    16
#define MAX_FILENAME_LEN 127

struct event {
    int pid;
    unsigned int state;
    unsigned long long duration_ns;
    bool exit_event;
    char comm[TASK_COMM_LEN];
};

#endif /* __BOOTSTRAP_H */
