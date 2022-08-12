### 1、Linux的缓存机制
- 高速缓存-Cache
  用于CPU和内存之间的缓冲，是在读取硬盘中的数据时，把最常用的数据保存在内存的缓存区中，再次读取该数据时，就不去硬盘中读取了，而在缓存中读取
- I/O缓存-Buffer
  用于内存和硬盘的缓冲，是在向硬盘写入数据时，先把数据放入缓冲区，然后再一起向硬盘写入，把分散的写操作集中进行，减少磁盘碎片和硬盘的反复寻道，从而提高系统性能。
  
简单的说，cache是加速读，而buffer是缓冲写，前者解决读的问题，保存从磁盘上读出的数据，后者是解决写的问题，保存即将要写入到磁盘上的数据。

### 2、文件系统的缓存机制
- inode缓存
  用哈希表来组织，当VFS访问索引节点时，它首先查找VFS索引节点缓存
```c
void __init inode_init(void)
{
	/* inode slab cache */
	inode_cachep = kmem_cache_create("inode_cache",
					 sizeof(struct inode),
					 0,
					 (SLAB_RECLAIM_ACCOUNT|SLAB_PANIC|
					 SLAB_MEM_SPREAD|SLAB_ACCOUNT),
					 init_once);

	/* Hash may have been set up in inode_init_early */
	if (!hashdist)
		return;

	inode_hashtable =
		alloc_large_system_hash("Inode-cache",
					sizeof(struct hlist_head),
					ihash_entries,
					14,
					HASH_ZERO,
					&i_hash_shift,
					&i_hash_mask,
					0,
					0);
}
```

- 目录项缓存-dcache
  用哈希表来组织，为了加快对常用的目录项的存取，由于是根据路径访问文件的，Linux维护了表达路径与索引节点对应关系的目录缓存，被文件系统使用过的目录将会存入到该目录缓存中。这样，同一目录被再次访问时，可直接从缓冲区得到，不必重复访问存储文件系统的设备。
```c
  static void __init dcache_init(void)
{
	/*
	 * A constructor could be added for stable state like the lists,
	 * but it is probably not worth it because of the cache nature
	 * of the dcache.
	 */
	dentry_cache = KMEM_CACHE_USERCOPY(dentry,
		SLAB_RECLAIM_ACCOUNT|SLAB_PANIC|SLAB_MEM_SPREAD|SLAB_ACCOUNT,
		d_iname);

	/* Hash may have been set up in dcache_init_early */
	if (!hashdist)
		return;

	dentry_hashtable =
		alloc_large_system_hash("Dentry cache",
					sizeof(struct hlist_bl_head),
					dhash_entries,
					13,
					HASH_ZERO,
					&d_hash_shift,
					NULL,
					0,
					0);
	d_hash_shift = 32 - d_hash_shift;
}
```
- 页缓存-Page cache
    - 当从文件中读取数据时，如果要读取的数据所在的页缓存已经存在，那么就直接把页缓存的数据拷贝给用户即可。否则，内核首先会申请一个空闲的内存页（页缓存），然后从文件中读取数据到页缓存，并且把页缓存的数据拷贝给用户。
    - 当向文件中写入数据时，如果要写入的数据所在的页缓存已经存在，那么直接把新数据写入到页缓存即可。否则，内核首先会申请一个空闲的内存页（页缓存），然后从文件中读取数据到页缓存，并且把新数据写入到页缓存中。对于被修改的页缓存，内核会定时把这些页缓存刷新到文件中。
早期的Linux内核版本中，同时存在Page Cache和Buffer Cache，前者用于缓存对文件操作的内容，后者用于缓存直接对块设备操作的内容。
page cache按照文件的逻辑页进行缓冲，buffer cache按照文件的物理块进行缓冲。
简单说来，page cache用来缓存文件数据，buffer cache用来缓存磁盘数据。在有文件系统的情况下，对文件操作，那么数据会缓存到page cache，如果直接采用dd等工具对磁盘进行读写，那么数据会缓存到buffer cache。
在内核版本2.4之后，对Page Cache、Buffer Cache的实现进行了融合，融合后的Buffer Cache不再以独立的形式存在，Buffer Cache的内容，直接存在于Page Cache中，同时，保留了对Buffer Cache的描述符单元：buffer_head。

从用户态文件打开到具体磁盘位置：
```c
struct file {
    ...
	struct inode		*f_inode;	/* cached value */
    ...
}
```
```c
struct inode {
    ...
    struct address_space	*i_mapping;
    ...
}
```
```c
struct address_space{
    ...
    struct radix_tree_root	page_tree;	/* radix tree of all pages */
    ...
}
```
```c
struct radix_tree_root{
    ...
    struct radix_tree_node	__rcu *rnode;
}
```
```c
struct radix_tree_node {
    ...
    void __rcu	*slots[RADIX_TREE_MAP_SIZE];
    ...
}
```
```c
struct page{
}
```
```c
struct buffer_head {
	...
	struct buffer_head *b_this_page;/* circular list of page's buffers */
    ...
}
```

如下图所示，使用open打开一个普通文件或者块文件的时候，会产生一个file结构或者是一个block_dev结构，该结构中的inode是文件的唯一标识符，其中字段address_space表示这个文件的地址空间，在这个地址空间中，所有存储相关数据的页面被关联在一棵基树radix_tree上，基树的每个子节点就是一个个页面page，而每个页面对应4个block，每个block用一个buffer_head结构来指向。
![pic9](./pic/pic9.jpg)


#### dcache-目录缓冲区
（关于dcache缓存命中率）

由于VFS会经常执行目录相关的操作，比如切换到某个目录、按照路径名进行的查找等等，为了提高效率，VFS引入了目录项的概念。
一个路径的组成部分，不管是目录还是普通文件，都是一个目录项对象。
不过目录项对象没有对应的磁盘数据结构，是VFS在遍历路径的过程中，将它们逐个解析成目录项对象。
将整个文件系统的目录结构解析成目录项，是一件费力的工作，为了节省VFS操作目录项的成本，内核会将目录项缓存起来，这就是目录项高速缓存dentry cache，也叫dcache。

目录项的代码如下：
```c
// /include/linux/dcache.h

struct dentry {
	/* RCU lookup touched fields */
	unsigned int d_flags;		/* 目录项缓存标识 */
	seqcount_t d_seq;		/* per dentry seqlock */
	struct hlist_bl_node d_hash;	/* lookup hash list */
	struct dentry *d_parent;	/* parent directory */
	struct qstr d_name;
	struct inode *d_inode;		/* Where the name belongs to - NULL is
					 * negative */
	unsigned char d_iname[DNAME_INLINE_LEN];	/* small names */

	/* Ref lookup also touches following */
	struct lockref d_lockref;	/* per-dentry lock and refcount */
	const struct dentry_operations *d_op;
	struct super_block *d_sb;	/* The root of the dentry tree */
	unsigned long d_time;		/* used by d_revalidate */
	void *d_fsdata;			/* fs-specific data */

	union {
		struct list_head d_lru;		/* LRU list */
		wait_queue_head_t *d_wait;	/* in-lookup ones only */
	};
	struct list_head d_child;	/* child of parent list */
	struct list_head d_subdirs;	/* our children */
	/*
	 * d_alias and d_rcu can share memory
	 */
	union {
		struct hlist_node d_alias;	/* inode alias list */
		struct hlist_bl_node d_in_lookup_hash;	/* only for in-lookup ones */
	 	struct rcu_head d_rcu;
	} d_u;
} __randomize_layout;

//引用计数
static inline unsigned d_count(const struct dentry *dentry)
{
	return dentry->d_lockref.count;
}
/*
struct lockref {
	union {
#if USE_CMPXCHG_LOCKREF
		aligned_u64 lock_count;
#endif
		struct {
			spinlock_t lock;
			int count;
		};
	};
};
*/
```

目录项有三种状态：
- 正在使用（inuse）状态：处于该状态下的dentry对象的引用计数d_count大于0，且其d_inode指向相关的inode对象。这种dentry对象不能被释放;
- 未使用（unused）状态：该dentry对象的引用计数d_count的值为0，但其d_inode指针仍然指向相关的的索引节点。该目录项仍然包含有效的信息，只是当前没有人引用他。这种dentry对象在回收内存时可能会被释放;
- 负（negative）状态：与目录项相关的inode对象不复存在（相应的磁盘索引节点可能已经被删除），dentry对象的d_inode指针为NULL。但这种dentry对象仍然保存在dcache中，以便后续对同一文件名的查找能够快速完成。这种dentry对象在回收内存时将首先被释放。
在结构体dentry_stat_t中：
```c
struct dentry_stat_t {
	long nr_dentry;
	long nr_unused;
	long age_limit;		/* age in seconds */
	long want_pages;	/* pages requested by system */
	long nr_negative;	/* # of unused negative dentries */
	long dummy;		/* Reserved for future use */
};
extern struct dentry_stat_t dentry_stat;
```
所以提取该结构体中的信息即可。


此外，获得这些数值对应的函数为：
```c
int proc_nr_dentry(struct ctl_table *table, int write, void __user *buffer,
		   size_t *lenp, loff_t *ppos)
{
	dentry_stat.nr_dentry = get_nr_dentry();
	dentry_stat.nr_unused = get_nr_dentry_unused();
	dentry_stat.nr_negative = get_nr_dentry_negative();
	return proc_doulongvec_minmax(table, write, buffer, lenp, ppos);
}
```

或者遍历dentry_hashtable算出总个数
```c

    dentry_hashtable =
        alloc_large_system_hash("Dentry cache",
                                sizeof(struct hlist_head),
                                dhash_entries,
                                13,
                                HASH_EARLY,
                                &d_hash_shift,
                                &d_hash_mask,
                                0);
    for (loop = 0; loop < (1 << d_hash_shift); loop++)
    {
        INIT_HLIST_HEAD(&dentry_hashtable[loop]);
```