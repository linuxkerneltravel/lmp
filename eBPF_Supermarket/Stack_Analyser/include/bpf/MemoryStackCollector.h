#ifndef _SA_MEMORY_H__
#define _SA_MEMORY_H__

#include "bpf/eBPFStackCollector.h"
#include "bpf/mem_count.skel.h"
#include <linux/version.h>

class MemoryStackCollector : public StackCollector
{
private:
    struct mem_count_bpf *skel = __null;

public:
    char *object = (char *)"libc.so.6";

protected:
    virtual double count_value(void *d);

public:
    MemoryStackCollector();

    virtual int load(void);
    virtual int attach(void);
    virtual void detach(void);
    virtual void unload(void);

/// @brief 向指定用户函数附加一个ebpf处理函数
/// @param skel ebpf程序骨架
/// @param sym_name 用户态函数名字面量，不加双引号
/// @param prog_name ebpf处理函数，skel->progs中的成员名
/// @param is_retprobe 布尔类型，是否附加到符号返回处
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 19, 0)
#define ATTACH_UPROBE(skel, sym_name, prog_name, is_retprobe)    \
    do                                                           \
    {                                                            \
        DECLARE_LIBBPF_OPTS(bpf_uprobe_opts, uprobe_opts,        \
                            .retprobe = is_retprobe);            \
        skel->links.prog_name = bpf_program__attach_uprobe_opts( \
            skel->progs.prog_name,                               \
            pid,                                                 \
            object,                                              \
            1,                                                   \
            &uprobe_opts);                                       \
    } while (false)
#else
#define ATTACH_UPROBE(skel, sym_name, prog_name, is_retprobe) \
    do                                                        \
    {                                                         \
        LIBBPF_OPTS(bpf_uprobe_opts, uprobe_opts,             \
                    .retprobe = is_retprobe,                  \
                    .func_name = #sym_name);                  \
        skel->links.prog_name =                               \
            bpf_program__attach_uprobe_opts(                  \
                skel->progs.prog_name,                        \
                pid,                                          \
                object,                                       \
                0,                                            \
                &uprobe_opts);                                \
    } while (false)
#endif

/// @brief 向指定用户函数附加一个处理函数并检查是否连接成功
/// @param skel ebpf程序骨架
/// @param sym_name 要连接的用户函数
/// @param prog_name ebpf处理函数
/// @param is_retprobe 布尔类型，是否附加到函数返回处
/// @note 如果检查到没有被附加则使上层函数返回负的错误代码
#define ATTACH_UPROBE_CHECKED(skel, sym_name, prog_name, is_retprobe)                 \
    do                                                                                \
    {                                                                                 \
        ATTACH_UPROBE(skel, sym_name, prog_name, is_retprobe);                        \
        CHECK_ERR(!skel->links.prog_name, "no program attached for " #prog_name "\n") \
    } while (false)

/// @brief 向指定用户态函数入口处附加一个处理函数并检查是否连接成功
/// @param skel ebpf程序骨架
/// @param sym_name 要跟踪的用户态函数名字面量，不带双引号
/// @param prog_name ebpf处理函数，skel->progs中的成员
/// @note 如果检查到没有被附加则使上层函数返回负的错误代码
#define at_ent(skel, sym_name, prog_name) ATTACH_UPROBE_CHECKED(skel, sym_name, prog_name, false)

/// @brief 向指定用户态函数返回处附加一个处理函数并检查是否连接成功
/// @param skel ebpf程序骨架
/// @param sym_name 要附加的用户态函数名，字面量，不带双引号
/// @param prog_name ebpf处理函数，skel->progs中的成员
/// @note 如果检查到没有被附加则使上层函数返回负的错误代码
#define at_ret(skel, sym_name, prog_name) ATTACH_UPROBE_CHECKED(skel, sym_name, prog_name, true)
};

#endif
