ahead.py
===

对于readahead的详细分析可以参考：  
[NOTE_Read-ahead源码分析](/docs/NOTE_Read-ahead源码分析.md)  

### 源码分析
#### 5.4的预读
```c
void page_cache_sync_readahead(struct address_space *mapping,
			       struct file_ra_state *ra, struct file *filp,
			       pgoff_t offset, unsigned long req_size)

static unsigned long
ondemand_readahead(struct address_space *mapping,
		   struct file_ra_state *ra, struct file *filp,
		   bool hit_readahead_marker, pgoff_t offset,
		   unsigned long req_size)

static inline unsigned long ra_submit(struct file_ra_state *ra,
		struct address_space *mapping, struct file *filp)

unsigned int __do_page_cache_readahead(struct address_space *mapping,
		struct file *filp, pgoff_t offset, unsigned long nr_to_read,
		unsigned long lookahead_size)

struct page *__page_cache_alloc(gfp_t gfp)
```

#### 5.15预读
```c
static inline
void page_cache_sync_readahead(struct address_space *mapping,
		struct file_ra_state *ra, struct file *file, pgoff_t index,
		unsigned long req_count)

void page_cache_sync_ra(struct readahead_control *ractl,
		unsigned long req_count)

static void ondemand_readahead(struct readahead_control *ractl,
		bool hit_readahead_marker, unsigned long req_size)

void do_page_cache_ra(struct readahead_control *ractl,
		unsigned long nr_to_read, unsigned long lookahead_size)

void page_cache_ra_unbounded(struct readahead_control *ractl,
		unsigned long nr_to_read, unsigned long lookahead_size)

static inline struct page *__page_cache_alloc(gfp_t gfp)
```

####  mark_page_accessed
/mm/swap.c - 5.15
```c
/*
 * Mark a page as having seen activity.
 *
 * inactive,unreferenced	->	inactive,referenced
 * inactive,referenced		->	active,unreferenced
 * active,unreferenced		->	active,referenced
 *
 * When a newly allocated page is not yet visible, so safe for non-atomic ops,
 * __SetPageReferenced(page) may be substituted for mark_page_accessed(page).
 */
void mark_page_accessed(struct page *page)
{
	page = compound_head(page);

	if (!PageReferenced(page)) {
		SetPageReferenced(page);
	} else if (PageUnevictable(page)) {
		/*
		 * Unevictable pages are on the "LRU_UNEVICTABLE" list. But,
		 * this list is never rotated or maintained, so marking an
		 * evictable page accessed has no effect.
		 */
	} else if (!PageActive(page)) {
		/*
		 * If the page is on the LRU, queue it for activation via
		 * lru_pvecs.activate_page. Otherwise, assume the page is on a
		 * pagevec, mark it active and it'll be moved to the active
		 * LRU on the next drain.
		 */
		if (PageLRU(page))
			activate_page(page);
		else
			__lru_cache_activate_page(page);
		ClearPageReferenced(page);
		workingset_activation(page);
	}
	if (page_is_idle(page))
		clear_page_idle(page);
}
```

#### 监测点确定
- page_cache_sync_readahead不能挂在监测程序：  
```sh
Exception: Failed to attach BPF program entry_readahead to kprobe page_cache_sync_readahead
```
出于兼容性的考虑于是选择监测`ondemand_readahead`:
```py
b.attach_kprobe(event="ondemand_readahead", fn_name="entry_readahead")
b.attach_kretprobe(event="ondemand_readahead", fn_name="exit_readahead")
b.attach_kretprobe(event="__page_cache_alloc", fn_name="exit_page_cache_alloc")
b.attach_kprobe(event="mark_page_accessed", fn_name="entry_mark_page_accessed")
```

### BPF程序
(以下代码只是片段)
#### 未使用的page个数
这部分是沿用了readahead脚本的功能：
```c
BPF_HASH(birth, struct page*, u64);

int exit_page_cache_alloc(struct pt_regs *ctx)
{
    ...
    struct page *retval = (struct page*)PT_REGS_RC(ctx);
    u64 ts = bpf_ktime_get_ns();
    birth.update(&retval, &ts);
    ...
}
int entry_mark_page_accessed(struct pt_regs *ctx)
{
    ...
    struct page *arg0 = (struct page *)PT_REGS_PARM1(ctx); 
    u64 *bts = birth.lookup(&arg0); 
    if (bts != NULL) {
        pages.atomic_increment(key, -1);
    }
    ...
}
```
打印：
```py
print("Read-ahead unused pages: %d" % (b["pages"][c_int.c_ulong(0)].value))
```

#### 从发起预读至使用到所申请页面的时间
映射表：
```c
BPF_HASH(delta, u64, u64); 
```
初始时间：
```c
int exit_page_cache_alloc(struct pt_regs *ctx)
{
    ...
    u64 ts = bpf_ktime_get_ns();
    struct page *retval = (struct page*)PT_REGS_RC(ctx);
    birth.update(&retval, &ts);
    ...
}
```
截止时间：
```c
int entry_mark_page_accessed(struct pt_regs *ctx)
{
    ...
    struct page *arg0 = (struct page *)PT_REGS_PARM1(ctx);  
    u64 *bts = birth.lookup(&arg0);
    u64 dt = ts - *bts;
    delta.atomic_increment(dt);
...
}
```
打印：
```py
delta = b.get_table("delta")
for k, v in sorted(delta.items())
    print(...)
```

#### 发起预读申请的进程信息
映射表：
```c
BPF_HASH(info, u64, struct data_t);
```
结构体：
```c
struct data_t
{
    u32 pid;
    char comm[TASK_COMM_LEN];
    u32 uid;
    u64 ts;
};
```
获得数据：
```c
int entry_readahead(struct pt_regs *ctx)
{
    struct data_t data = {};

    u64 id = bpf_get_current_pid_tgid();

    u32 pid = id >> 32;
    data.pid = pid;
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    data.uid = bpf_get_current_uid_gid();
    data.ts = bpf_ktime_get_ns();
    info.update(&id, &data);
}
```
打印：
```py
info = b.get_table("info")
for k, v in sorted(info.items())
    print(...)
```

### 运行结果
输出间隔设置为5s:
```sh
# ./ahead.py 
TIME: 19:18:35 
Read-ahead unused pages: 0
Cost time(get page->mark acessed) and num - 0 items
Do_read-ahead info:
```
无预读动作时，所有计数均为0。
```sh
TIME: 19:18:40 
Read-ahead unused pages: 0
Cost time(get page->mark acessed) and num - 3 items
735316(ms):1   208374(ms):1   98750(ms):1   
Do_read-ahead info:
1:   Count=1 pid=30365 user=zhangfan[1000] comm=nautilus 
2:   Count=1 pid=16672 user=zhangfan[1000] comm=pool-gnome-shel 
3:   Count=1 pid=17410 user=zhangfan[1000] comm=tracker-miner-f 
```
- 结果第一行打印了当前时间；  
- 第二行表示当前未使用的page个数为0；  
- 第三行表示有3个项目得到了申请的页面；  
- 第四行打印了耗时；  
- 第五行开始输出发起预读的进程信息并记录他们的发起次数。

