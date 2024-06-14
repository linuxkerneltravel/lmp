// Copyright 2023 The LMP Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// https://github.com/linuxkerneltravel/lmp/blob/develop/LICENSE
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// author: blown.away@qq.com
//
// netwatcher libbpf 内核<->用户 传递信息相关结构体

#ifndef __MYSQL_HELPER_BPF_H
#define __MYSQL_HELPER_BPF_H

#include "netwatcher.h"
#include "vmlinux.h"
#include <asm-generic/errno.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <string.h>

enum enum_server_command {
    COM_SLEEP,
    COM_QUIT,
    COM_INIT_DB,
    COM_QUERY,
    COM_FIELD_LIST,
    COM_CREATE_DB,
    COM_DROP_DB,
    COM_REFRESH,
    COM_SHUTDOWN,
    COM_STATISTICS,
    COM_PROCESS_INFO,
    COM_CONNECT,
    COM_PROCESS_KILL,
    COM_DEBUG,
    COM_PING,
    COM_TIME,
    COM_DELAYED_INSERT,
    COM_CHANGE_USER,
    COM_BINLOG_DUMP,
    COM_TABLE_DUMP,
    COM_CONNECT_OUT,
    COM_REGISTER_SLAVE,
    COM_STMT_PREPARE,
    COM_STMT_EXECUTE,
    COM_STMT_SEND_LONG_DATA,
    COM_STMT_CLOSE,
    COM_STMT_RESET,
    COM_SET_OPTION,
    COM_STMT_FETCH,
    COM_DAEMON,
    COM_BINLOG_DUMP_GTID,
    COM_RESET_CONNECTION,
    /* don't forget to update const char *command_name[] in sql_parse.cc */
    /* Must be last */
    COM_END
};

typedef struct st_com_init_db_data {
    const char *db_name;
    unsigned long length;
} COM_INIT_DB_DATA;

#define MYSQL_SHUTDOWN_KILLABLE_CONNECT (unsigned char)(1 << 0)
#define MYSQL_SHUTDOWN_KILLABLE_TRANS (unsigned char)(1 << 1)
#define MYSQL_SHUTDOWN_KILLABLE_LOCK_TABLE (unsigned char)(1 << 2)
#define MYSQL_SHUTDOWN_KILLABLE_UPDATE (unsigned char)(1 << 3)

#define LOCK_MODE_MASK 0xFUL
#define LOCK_TYPE_MASK 0xF0UL

enum mysql_enum_shutdown_level {
    SHUTDOWN_DEFAULT = 0,
    SHUTDOWN_WAIT_CONNECTIONS = MYSQL_SHUTDOWN_KILLABLE_CONNECT,
    SHUTDOWN_WAIT_TRANSACTIONS = MYSQL_SHUTDOWN_KILLABLE_TRANS,
    SHUTDOWN_WAIT_UPDATES = MYSQL_SHUTDOWN_KILLABLE_UPDATE,
    SHUTDOWN_WAIT_ALL_BUFFERS = (MYSQL_SHUTDOWN_KILLABLE_UPDATE << 1),
    SHUTDOWN_WAIT_CRITICAL_BUFFERS = (MYSQL_SHUTDOWN_KILLABLE_UPDATE << 1) + 1,
    KILL_QUERY = 254,
    KILL_CONNECTION = 255
};

typedef struct st_com_refresh_data {
    unsigned char options;
} COM_REFRESH_DATA;

typedef struct st_com_shutdown_data {
    enum mysql_enum_shutdown_level level;
} COM_SHUTDOWN_DATA;

typedef struct st_com_kill_data {
    unsigned long id;
} COM_KILL_DATA;

typedef struct st_com_set_option_data {
    unsigned int opt_command;
} COM_SET_OPTION_DATA;

typedef struct st_com_stmt_execute_data {
    unsigned long stmt_id;
    unsigned long flags;
    unsigned char *params;
    unsigned long params_length;
} COM_STMT_EXECUTE_DATA;

typedef struct st_com_stmt_fetch_data {
    unsigned long stmt_id;
    unsigned long num_rows;
} COM_STMT_FETCH_DATA;

typedef struct st_com_stmt_send_long_data_data {
    unsigned long stmt_id;
    unsigned int param_number;
    unsigned char *longdata;
    unsigned long length;
} COM_STMT_SEND_LONG_DATA_DATA;

typedef struct st_com_stmt_prepare_data {
    const char *query;
    unsigned int length;
} COM_STMT_PREPARE_DATA;

typedef struct st_stmt_close_data {
    unsigned int stmt_id;
} COM_STMT_CLOSE_DATA;

typedef struct st_com_stmt_reset_data {
    unsigned int stmt_id;
} COM_STMT_RESET_DATA;

typedef struct st_com_query_data {
    const char *query;
    unsigned int length;
} COM_QUERY_DATA;

typedef struct st_com_field_list_data {
    unsigned char *table_name;
    unsigned int table_name_length;
    const unsigned char *query;
    unsigned int query_length;
} COM_FIELD_LIST_DATA;

union COM_DATA {
    COM_INIT_DB_DATA com_init_db;
    COM_REFRESH_DATA com_refresh;
    COM_SHUTDOWN_DATA com_shutdown;
    COM_KILL_DATA com_kill;
    COM_SET_OPTION_DATA com_set_option;
    COM_STMT_EXECUTE_DATA com_stmt_execute;
    COM_STMT_FETCH_DATA com_stmt_fetch;
    COM_STMT_SEND_LONG_DATA_DATA com_stmt_send_long_data;
    COM_STMT_PREPARE_DATA com_stmt_prepare;
    COM_STMT_CLOSE_DATA com_stmt_close;
    COM_STMT_RESET_DATA com_stmt_reset;
    COM_QUERY_DATA com_query;
    COM_FIELD_LIST_DATA com_field_list;
};

/* help functions end */

#endif
