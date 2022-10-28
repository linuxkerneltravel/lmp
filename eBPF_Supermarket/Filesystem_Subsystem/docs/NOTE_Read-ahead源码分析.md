
### 预读流程梳理
基于Linux 5.4

#### 1、do_generic_file_read()
find_get_page 表示在文件 inode 节点的 address_space 中寻找所需要的页偏移的页：
```c
find_page:
		page = find_get_page(mapping, index);
```

如果找不到，启动同步预读函数 page_cache_sync_readahead(),同步预读函数结束后，需要的缓冲页应该就被加入到 inode 节点的 address_space 中，除非缓冲页没有了，分配不到。如果分配不到的话，就跳转到 label no_cached_page::
```c
		if (!page) {
			page_cache_sync_readahead(mapping,
					ra, filp,
					index, last_index - index);
			page = find_get_page(mapping, index);
			if (unlikely(page == NULL))
				goto no_cached_page;
		}
```

找到 page 后，通过PageReadahead判断此页是否是标记好的预读页（判断页面的是否设置了PG_readahead），如果是说明进程是在按照我们的预计顺序读取，启动异步预读:
```c
		if (PageReadahead(page)) {
			page_cache_async_readahead(mapping,
					ra, filp, page,
					index, last_index - index);
		}
```
<font color=red>
PS：     
</font>

关于同步预读和异步预读的区别：  
page_cache_async_readahead()函数的参数和同步预读一样，只多一个struct page结构体，作用是将该page的PG_readahead的标志清空（`ClearPageReadahead(page)`），接着也是调用ondemand_readahead()函数。  
我们发现generic_file_buffered_read()发起的同步预读和异步预读最终都是调用ondemand_readahead()函数，区别是第四个传参hit_readahead_marker为true或false。  

#### 2、page_cache_sync_readahead()
```c
void page_cache_sync_readahead(struct address_space *mapping,
			       struct file_ra_state *ra, struct file *filp,
			       pgoff_t offset, unsigned long req_size)
{
	/* no read-ahead */
	if (!ra->ra_pages)
		return;

	if (blk_cgroup_congested())
		return;

	/* be dumb */
	if (filp && (filp->f_mode & FMODE_RANDOM)) {
		force_page_cache_readahead(mapping, filp, offset, req_size);
		return;
	}

	/* do read-ahead */
	ondemand_readahead(mapping, ra, filp, false, offset, req_size);
}
```
若预读的最大页数为 0 ，则表示不进行预读，直接返回。  
若文件打开的方式为随机方式，调用 force_page_cache_readahead() 。  
调用 ondemand_readahead() 启动预读。  

#### 3、ondemand_readahead()
首先判断如果是从文件头开始读取的，则认为是顺序读，初始化预读信息，默认设置预读为4个page：
```c
static unsigned long
ondemand_readahead(struct address_space *mapping,
		   struct file_ra_state *ra, struct file *filp,
		   bool hit_readahead_marker, pgoff_t offset,
		   unsigned long req_size)
{
...
	/*
	 * start of file
	 */
	if (!offset)
		goto initial_readahead;
...
initial_readahead:
	ra->start = offset;
	ra->size = get_init_ra_size(req_size, max_pages);
	ra->async_size = ra->size > req_size ? ra->size - req_size : ra->size;
```

如果不是从文件头开始读，则判断是否是连续的读取请求，如果是则扩大预读数量，一般等于上次预读数量的二倍：
```c
	/*
	 * It's the expected callback offset, assume sequential access.
	 * Ramp up sizes, and push forward the readahead window.
	 */
	if ((offset == (ra->start + ra->size - ra->async_size) ||
	     offset == (ra->start + ra->size))) {
		ra->start += ra->size;
		ra->size = get_next_ra_size(ra, max_pages);
		ra->async_size = ra->size;
		goto readit;
	}
...
readit:
	/*
	 * Will this read hit the readahead marker made by itself?
	 * If so, trigger the readahead marker hit now, and merge
	 * the resulted next readahead window into the current one.
	 * Take care of maximum IO pages as above.
	 */
	if (offset == ra->start && ra->size == ra->async_size) {
		add_pages = get_next_ra_size(ra, max_pages);
		if (ra->size + add_pages <= max_pages) {
			ra->async_size = add_pages;
			ra->size += add_pages;
		} else {
			ra->size = max_pages;
			ra->async_size = max_pages >> 1;
		}
	}

	return ra_submit(ra, mapping, filp);
}
```

否则就是随机的读取，直接调用核心函数：
```c
	/*
	 * standalone, small random read
	 * Read as is, and do not pollute the readahead state.
	 */
	return __do_page_cache_readahead(mapping, filp, offset, req_size, 0);
```

调用 ra_submit() 提交读请求：
```c
	return ra_submit(ra, mapping, filp);
```

#### 4、ra_submit()
```c
static inline unsigned long ra_submit(struct file_ra_state *ra,
		struct address_space *mapping, struct file *filp)
{
	return __do_page_cache_readahead(mapping, filp,
					ra->start, ra->size, ra->async_size);
}
```
实际上是__do_page_cache_readahead的一层封装

#### 5、__do_page_cache_readahead()
这个函数实际做的是从磁盘进行读取，首先分配页面，然后提交给IO（雾  
返回值是所需页面的数量，或者是IO所允许的最大数量
```c
unsigned int __do_page_cache_readahead(struct address_space *mapping,
		struct file *filp, pgoff_t offset, unsigned long nr_to_read,
		unsigned long lookahead_size)
{
	struct inode *inode = mapping->host;
	struct page *page;
	unsigned long end_index;	/* The last page we want to read */
	LIST_HEAD(page_pool);
	int page_idx;
	unsigned int nr_pages = 0;
	loff_t isize = i_size_read(inode);
	gfp_t gfp_mask = readahead_gfp_mask(mapping);

	if (isize == 0)
		goto out;

	end_index = ((isize - 1) >> PAGE_SHIFT);

	/*
	 * Preallocate as many pages as we will need.
	 */
	for (page_idx = 0; page_idx < nr_to_read; page_idx++) {
		pgoff_t page_offset = offset + page_idx;

		if (page_offset > end_index)
			break;

		page = xa_load(&mapping->i_pages, page_offset);
		if (page && !xa_is_value(page)) {
			/*
			 * Page already present?  Kick off the current batch of
			 * contiguous pages before continuing with the next
			 * batch.
			 */
			if (nr_pages)
				read_pages(mapping, filp, &page_pool, nr_pages,
						gfp_mask);
			nr_pages = 0;
			continue;
		}

		page = __page_cache_alloc(gfp_mask);
		if (!page)
			break;
		page->index = page_offset;
		list_add(&page->lru, &page_pool);
		if (page_idx == nr_to_read - lookahead_size)
			SetPageReadahead(page);
		nr_pages++;
	}

	/*
	 * Now start the IO.  We ignore I/O errors - if the page is not
	 * uptodate then the caller will launch readpage again, and
	 * will then handle the error.
	 */
	if (nr_pages)
		read_pages(mapping, filp, &page_pool, nr_pages, gfp_mask);
	BUG_ON(!list_empty(&page_pool));
out:
	return nr_pages;
}
```
在分配内存前，首先检查页面是否已经在 cache 中，因为别的进程可能已经将某些页面读进内存了。若页面 cache 中没有，则分配内存页，并将页面加入页面池（page_pool）:`page = __page_cache_alloc(gfp_mask);`  
当分配到第`nr_to_read - lookahead_size`个页面时，表示达到了最大数量，设置该页面标志PG_readahead，让下一次异步预读去进行操作。  
页面准备好，调用`read_pages`读取文件数据。  

####  6、__page_cache_alloc()
```c
struct page *__page_cache_alloc(gfp_t gfp)
{
	int n;
	struct page *page;

	if (cpuset_do_page_mem_spread()) {
		unsigned int cpuset_mems_cookie;
		do {
			cpuset_mems_cookie = read_mems_allowed_begin();
			n = cpuset_mem_spread_node();
			page = __alloc_pages_node(n, gfp, 0);
		} while (!page && read_mems_allowed_retry(cpuset_mems_cookie));

		return page;
	}
	return alloc_pages(gfp, 0);
}
```
最终alloc_pages分配好页面后返回一个page结构体。

#### 总结
所以说去监控一个线程的__do_page_cache_readahead()表示经过了这些判断：  
1. `find_get_page`在文件 inode 节点的 address_space 中寻找所需要的页偏移的页;  
2. 没有找到，于是启动同步预读函数`page_cache_sync_readahead()`去磁盘中加载；  
3. 进行一系列判断后调用`ondemand_readahead()`启动预读;  
4. 调用`ra_submit()`提交读请求;  
5. `__do_page_cache_readahead()`首先检查页面是否已经在cache中，若没有则用`__page_cache_alloc`分配内存页，并将页面加入页面池;  
6. `__page_cache_alloc`返回分配好的page结构体。    
<font color=red>
PS：  
</font>
`__do_page_cache_readahead()`首先检查页面是否已经在cache中，是否就可以算出页面的命中率？



参考：
<https://blog.csdn.net/weixin_42205011/article/details/97669486?spm=1001.2014.3001.5502>  
<https://blog.csdn.net/weixin_42205011/article/details/97890676>  
<https://zhuanlan.zhihu.com/p/540193166>




5.15内核没有__do_page_cache_readahead函数了，变动部分见下：
### 5.15源码分析
#### 1、page_cache_sync_readahead
/include/linux/pagemap.h
```c
static inline
void page_cache_sync_readahead(struct address_space *mapping,
		struct file_ra_state *ra, struct file *file, pgoff_t index,
		unsigned long req_count)
{
	DEFINE_READAHEAD(ractl, file, ra, mapping, index);
	page_cache_sync_ra(&ractl, req_count);
}
```
同步预读函数page_cache_sync_readahead发生在缓存未命中的情况下，同步预读函数结束后，需要的缓冲页应该就被加入到 inode 节点的 address_space 中，除非缓冲页没有了，分配不到。  

#### 2、page_cache_sync_ra
/mm/readahead.c
```c
void page_cache_sync_ra(struct readahead_control *ractl,
		unsigned long req_count)
{
	bool do_forced_ra = ractl->file && (ractl->file->f_mode & FMODE_RANDOM);

	/*
	 * Even if read-ahead is disabled, issue this request as read-ahead
	 * as we'll need it to satisfy the requested range. The forced
	 * read-ahead will do the right thing and limit the read to just the
	 * requested range, which we'll set to 1 page for this case.
	 */
	if (!ractl->ra->ra_pages || blk_cgroup_congested()) {
		if (!ractl->file)
			return;
		req_count = 1;
		do_forced_ra = true;
	}

	/* be dumb */
	if (do_forced_ra) {
		force_page_cache_ra(ractl, req_count);
		return;
	}

	/* do read-ahead */
	ondemand_readahead(ractl, false, req_count);
}
EXPORT_SYMBOL_GPL(page_cache_sync_ra);
```

#### 3、ondemand_readahead
/mm/readahead.c
```c
static void ondemand_readahead(struct readahead_control *ractl,
		bool hit_readahead_marker, unsigned long req_size)
{
    struct backing_dev_info *bdi = inode_to_bdi(ractl->mapping->host);
	struct file_ra_state *ra = ractl->ra;
	unsigned long max_pages = ra->ra_pages;
	unsigned long add_pages;
	unsigned long index = readahead_index(ractl);
	pgoff_t prev_index;

...
	/*
	 * standalone, small random read
	 * Read as is, and do not pollute the readahead state.
	 */
	do_page_cache_ra(ractl, req_size, 0);
	return;
...
initial_readahead:
...

readit:
	/*
	 * Will this read hit the readahead marker made by itself?
	 * If so, trigger the readahead marker hit now, and merge
	 * the resulted next readahead window into the current one.
	 * Take care of maximum IO pages as above.
	 */
...

	ractl->_index = ra->start;
	do_page_cache_ra(ractl, ra->size, ra->async_size);
}
```

#### 4、do_page_cache_ra
/mm/readahead.c
```c
/*
 * do_page_cache_ra() actually reads a chunk of disk.  It allocates
 * the pages first, then submits them for I/O. This avoids the very bad
 * behaviour which would occur if page allocations are causing VM writeback.
 * We really don't want to intermingle reads and writes like that.
 */
void do_page_cache_ra(struct readahead_control *ractl,
		unsigned long nr_to_read, unsigned long lookahead_size)
{
	struct inode *inode = ractl->mapping->host;
	unsigned long index = readahead_index(ractl);
	loff_t isize = i_size_read(inode);
	pgoff_t end_index;	/* The last page we want to read */

	if (isize == 0)
		return;

	end_index = (isize - 1) >> PAGE_SHIFT;
	if (index > end_index)
		return;
	/* Don't read past the page containing the last byte of the file */
	if (nr_to_read > end_index - index)
		nr_to_read = end_index - index + 1;

	page_cache_ra_unbounded(ractl, nr_to_read, lookahead_size);
}
```

#### 5、page_cache_ra_unbounded
/mm/readahead.c
```c
/**
 * page_cache_ra_unbounded - Start unchecked readahead.
 * @ractl: Readahead control.
 * @nr_to_read: The number of pages to read.
 * @lookahead_size: Where to start the next readahead.
 *
 * This function is for filesystems to call when they want to start
 * readahead beyond a file's stated i_size.  This is almost certainly
 * not the function you want to call.  Use page_cache_async_readahead()
 * or page_cache_sync_readahead() instead.
 *
 * Context: File is referenced by caller.  Mutexes may be held by caller.
 * May sleep, but will not reenter filesystem to reclaim memory.
 */
void page_cache_ra_unbounded(struct readahead_control *ractl,
		unsigned long nr_to_read, unsigned long lookahead_size)
{
	struct address_space *mapping = ractl->mapping;
	unsigned long index = readahead_index(ractl);
	LIST_HEAD(page_pool);
	gfp_t gfp_mask = readahead_gfp_mask(mapping);
	unsigned long i;

	/*
	 * Partway through the readahead operation, we will have added
	 * locked pages to the page cache, but will not yet have submitted
	 * them for I/O.  Adding another page may need to allocate memory,
	 * which can trigger memory reclaim.  Telling the VM we're in
	 * the middle of a filesystem operation will cause it to not
	 * touch file-backed pages, preventing a deadlock.  Most (all?)
	 * filesystems already specify __GFP_NOFS in their mapping's
	 * gfp_mask, but let's be explicit here.
	 */
	unsigned int nofs = memalloc_nofs_save();

	filemap_invalidate_lock_shared(mapping);
	/*
	 * Preallocate as many pages as we will need.
	 */
	for (i = 0; i < nr_to_read; i++) {
		struct page *page = xa_load(&mapping->i_pages, index + i);

		if (page && !xa_is_value(page)) {
			/*
			 * Page already present?  Kick off the current batch
			 * of contiguous pages before continuing with the
			 * next batch.  This page may be the one we would
			 * have intended to mark as Readahead, but we don't
			 * have a stable reference to this page, and it's
			 * not worth getting one just for that.
			 */
			read_pages(ractl, &page_pool, true);
			i = ractl->_index + ractl->_nr_pages - index - 1;
			continue;
		}

		page = __page_cache_alloc(gfp_mask);
		if (!page)
			break;
		if (mapping->a_ops->readpages) {
			page->index = index + i;
			list_add(&page->lru, &page_pool);
		} else if (add_to_page_cache_lru(page, mapping, index + i,
					gfp_mask) < 0) {
			put_page(page);
			read_pages(ractl, &page_pool, true);
			i = ractl->_index + ractl->_nr_pages - index - 1;
			continue;
		}
		if (i == nr_to_read - lookahead_size)
			SetPageReadahead(page);
		ractl->_nr_pages++;
	}

	/*
	 * Now start the IO.  We ignore I/O errors - if the page is not
	 * uptodate then the caller will launch readpage again, and
	 * will then handle the error.
	 */
	read_pages(ractl, &page_pool, false);
	filemap_invalidate_unlock_shared(mapping);
	memalloc_nofs_restore(nofs);
}
EXPORT_SYMBOL_GPL(page_cache_ra_unbounded);
```

#### 6、__page_cache_alloc
/include/linux/pagemap.h
```c
static inline struct page *__page_cache_alloc(gfp_t gfp)
{
	return alloc_pages(gfp, 0);
}
```






