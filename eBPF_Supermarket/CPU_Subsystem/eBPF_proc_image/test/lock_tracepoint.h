
#undef LTTNG_UST_TRACEPOINT_PROVIDER
#define LTTNG_UST_TRACEPOINT_PROVIDER lock_monitor

#undef LTTNG_UST_TRACEPOINT_INCLUDE
#define LTTNG_UST_TRACEPOINT_INCLUDE "/home/xhb/ospp/lock_tracepoint.h"

#if !defined(LOCK_TRACEPOINT_H) || defined(LTTNG_UST_TRACEPOINT_HEADER_MULTI_READ)
#define LOCK_TRACEPOINT_H

#include <lttng/tracepoint.h>

TRACEPOINT_EVENT(
    lock_monitor,
    mutex_lock_start,
    TP_ARGS(int, thread_id, void*, lock_ptr, long long unsigned int, time),
    TP_FIELDS(
        ctf_integer(int, thread_id, thread_id)
        ctf_integer_hex(void*, lock_ptr, lock_ptr)
        ctf_integer(long long unsigned int, time, time)
    )
)

TRACEPOINT_EVENT(
    lock_monitor,
    mutex_lock_acquired,
    TP_ARGS(int, thread_id, void*, lock_ptr, long long unsigned int, time),
    TP_FIELDS(
        ctf_integer(int, thread_id, thread_id)
        ctf_integer_hex(void*, lock_ptr, lock_ptr)
        ctf_integer(long long unsigned int, time, time)
    )
)

TRACEPOINT_EVENT(
    lock_monitor,
    mutex_lock_released,
    TP_ARGS(int, thread_id, void*, lock_ptr, long long unsigned int, time),
    TP_FIELDS(
        ctf_integer(int, thread_id, thread_id)
        ctf_integer_hex(void*, lock_ptr, lock_ptr)
        ctf_integer(long long unsigned int, time, time)
    )
)

TRACEPOINT_EVENT(
    lock_monitor,
    mutex_trylock_start,
    TP_ARGS(int, thread_id, void*, lock_ptr, long long unsigned int, time),
    TP_FIELDS(
        ctf_integer(int, thread_id, thread_id)
        ctf_integer_hex(void*, lock_ptr, lock_ptr)
        ctf_integer(long long unsigned int, time, time)
    )
)

TRACEPOINT_EVENT(
    lock_monitor,
    mutex_trylock_acquired,
    TP_ARGS(int, thread_id, void*, lock_ptr, long long unsigned int, time),
    TP_FIELDS(
        ctf_integer(int, thread_id, thread_id)
        ctf_integer_hex(void*, lock_ptr, lock_ptr)
        ctf_integer(long long unsigned int, time, time)
    )
)

TRACEPOINT_EVENT(
    lock_monitor,
    mutex_trylock_failed,
    TP_ARGS(int, thread_id, void*, lock_ptr, long long unsigned int, time),
    TP_FIELDS(
        ctf_integer(int, thread_id, thread_id)
        ctf_integer_hex(void*, lock_ptr, lock_ptr)
        ctf_integer(long long unsigned int, time, time)
    )
)

TRACEPOINT_EVENT(
    lock_monitor,
    rwlock_rdlock_start,
    TP_ARGS(int, thread_id, void*, lock_ptr, long long unsigned int, time),
    TP_FIELDS(
        ctf_integer(int, thread_id, thread_id)
        ctf_integer_hex(void*, lock_ptr, lock_ptr)
        ctf_integer(long long unsigned int, time, time)
    )
)

TRACEPOINT_EVENT(
    lock_monitor,
    rwlock_rdlock_acquired,
    TP_ARGS(int, thread_id, void*, lock_ptr, long long unsigned int, time),
    TP_FIELDS(
        ctf_integer(int, thread_id, thread_id)
        ctf_integer_hex(void*, lock_ptr, lock_ptr)
        ctf_integer(long long unsigned int, time, time)
    )
)

TRACEPOINT_EVENT(
    lock_monitor,
    rwlock_rdlock_released,
    TP_ARGS(int, thread_id, void*, lock_ptr, long long unsigned int, time),
    TP_FIELDS(
        ctf_integer(int, thread_id, thread_id)
        ctf_integer_hex(void*, lock_ptr, lock_ptr)
        ctf_integer(long long unsigned int, time, time)
    )
)
TRACEPOINT_EVENT(
    lock_monitor,
    rwlock_rdlock_failed,
    TP_ARGS(int, thread_id, void*, lock_ptr, long long unsigned int, time),
    TP_FIELDS(
        ctf_integer(int, thread_id, thread_id)
        ctf_integer_hex(void*, lock_ptr, lock_ptr)
        ctf_integer(long long unsigned int, time, time)
    )
)

TRACEPOINT_EVENT(
    lock_monitor,
    rwlock_wrlock_start,
    TP_ARGS(int, thread_id, void*, lock_ptr, long long unsigned int, time),
    TP_FIELDS(
        ctf_integer(int, thread_id, thread_id)
        ctf_integer_hex(void*, lock_ptr, lock_ptr)
        ctf_integer(long long unsigned int, time, time)
    )
)

TRACEPOINT_EVENT(
    lock_monitor,
    rwlock_wrlock_acquired,
    TP_ARGS(int, thread_id, void*, lock_ptr, long long unsigned int, time),
    TP_FIELDS(
        ctf_integer(int, thread_id, thread_id)
        ctf_integer_hex(void*, lock_ptr, lock_ptr)
        ctf_integer(long long unsigned int, time, time)
    )
)

TRACEPOINT_EVENT(
    lock_monitor,
    rwlock_wrlock_released,
    TP_ARGS(int, thread_id, void*, lock_ptr, long long unsigned int, time),
    TP_FIELDS(
        ctf_integer(int, thread_id, thread_id)
        ctf_integer_hex(void*, lock_ptr, lock_ptr)
        ctf_integer(long long unsigned int, time, time)
    )
)

TRACEPOINT_EVENT(
    lock_monitor,
    rwlock_wrlock_failed,
    TP_ARGS(int, thread_id, void*, lock_ptr, long long unsigned int, time),
    TP_FIELDS(
        ctf_integer(int, thread_id, thread_id)
        ctf_integer_hex(void*, lock_ptr, lock_ptr)
        ctf_integer(long long unsigned int, time, time)
    )
)

TRACEPOINT_EVENT(
    lock_monitor,
    spinlock_lock_start,
    TP_ARGS(int, thread_id, void*, lock_ptr, long long unsigned int, time),
    TP_FIELDS(
        ctf_integer(int, thread_id, thread_id)
        ctf_integer_hex(void*, lock_ptr, lock_ptr)
        ctf_integer(long long unsigned int, time, time)
    )
)

TRACEPOINT_EVENT(
    lock_monitor,
    spinlock_lock_acquired,
    TP_ARGS(int, thread_id, void*, lock_ptr, long long unsigned int, time),
    TP_FIELDS(
        ctf_integer(int, thread_id, thread_id)
        ctf_integer_hex(void*, lock_ptr, lock_ptr)
        ctf_integer(long long unsigned int, time, time)
    )
)

TRACEPOINT_EVENT(
    lock_monitor,
    spinlock_lock_released,
    TP_ARGS(int, thread_id, void*, lock_ptr, long long unsigned int, time),
    TP_FIELDS(
        ctf_integer(int, thread_id, thread_id)
        ctf_integer_hex(void*, lock_ptr, lock_ptr)
        ctf_integer(long long unsigned int, time, time)
    )
)

TRACEPOINT_EVENT(
    lock_monitor,
    spinlock_trylock_start,
    TP_ARGS(int, thread_id, void*, lock_ptr, long long unsigned int, time),
    TP_FIELDS(
        ctf_integer(int, thread_id, thread_id)
        ctf_integer_hex(void*, lock_ptr, lock_ptr)
        ctf_integer(long long unsigned int, time, time)
    )
)

TRACEPOINT_EVENT(
    lock_monitor,
    spinlock_trylock_acquired,
    TP_ARGS(int, thread_id, void*, lock_ptr, long long unsigned int, time),
    TP_FIELDS(
        ctf_integer(int, thread_id, thread_id)
        ctf_integer_hex(void*, lock_ptr, lock_ptr)
        ctf_integer(long long unsigned int, time, time)
    )
)

TRACEPOINT_EVENT(
    lock_monitor,
    spinlock_trylock_failed,
    TP_ARGS(int, thread_id, void*, lock_ptr, long long unsigned int, time),
    TP_FIELDS(
        ctf_integer(int, thread_id, thread_id)
        ctf_integer_hex(void*, lock_ptr, lock_ptr)
        ctf_integer(long long unsigned int, time, time)
    )
)
TRACEPOINT_LOGLEVEL(lock_monitor, mutex_lock_start, TRACE_DEBUG)
TRACEPOINT_LOGLEVEL(lock_monitor, mutex_lock_acquired, TRACE_DEBUG)
TRACEPOINT_LOGLEVEL(lock_monitor, mutex_lock_released, TRACE_DEBUG)
TRACEPOINT_LOGLEVEL(lock_monitor, mutex_trylock_start, TRACE_DEBUG)
TRACEPOINT_LOGLEVEL(lock_monitor, mutex_trylock_acquired, TRACE_DEBUG)
TRACEPOINT_LOGLEVEL(lock_monitor, mutex_trylock_failed, TRACE_DEBUG)

TRACEPOINT_LOGLEVEL(lock_monitor, rwlock_rdlock_start, TRACE_DEBUG)
TRACEPOINT_LOGLEVEL(lock_monitor, rwlock_rdlock_acquired, TRACE_DEBUG)
TRACEPOINT_LOGLEVEL(lock_monitor, rwlock_rdlock_released, TRACE_DEBUG)
TRACEPOINT_LOGLEVEL(lock_monitor, rwlock_rdlock_failed, TRACE_DEBUG)
TRACEPOINT_LOGLEVEL(lock_monitor, rwlock_wrlock_start, TRACE_DEBUG)
TRACEPOINT_LOGLEVEL(lock_monitor, rwlock_wrlock_acquired, TRACE_DEBUG)
TRACEPOINT_LOGLEVEL(lock_monitor, rwlock_wrlock_released, TRACE_DEBUG)
TRACEPOINT_LOGLEVEL(lock_monitor, rwlock_wrlock_failed, TRACE_DEBUG)

TRACEPOINT_LOGLEVEL(lock_monitor, spinlock_lock_start, TRACE_DEBUG)
TRACEPOINT_LOGLEVEL(lock_monitor, spinlock_lock_acquired, TRACE_DEBUG)
TRACEPOINT_LOGLEVEL(lock_monitor, spinlock_lock_released, TRACE_DEBUG)
TRACEPOINT_LOGLEVEL(lock_monitor, spinlock_trylock_start, TRACE_DEBUG)
TRACEPOINT_LOGLEVEL(lock_monitor, spinlock_trylock_acquired, TRACE_DEBUG)
TRACEPOINT_LOGLEVEL(lock_monitor, spinlock_trylock_failed, TRACE_DEBUG)


#endif /* LOCK_TRACEPOINT_H */

#include <lttng/tracepoint-event.h>
