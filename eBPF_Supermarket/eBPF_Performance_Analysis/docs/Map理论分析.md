# Map理论分析

在测试之前，我们需要先对需要测试的Map类型进行一个详细的理论分析，通过对Map的理论分析，来得到一个有利的理论指导，并通过这个指导来设计测试方案并且验证测试结果的正确性。

## 一、特征与源码分析

### **1.BPF_MAP_TYPE_HASH**

- 在eBPF中，HashMap实际上是一个哈希表，用于将键映射到值。它使用哈希函数来计算键的哈希值，并将其映射到一个存储桶（bucket）中。
- 哈希表内部由一个数组（buckets）和链表（或者是红黑树）组成。数组中的每个元素是一个链表头或树的根节点，用于处理哈希冲突。
- HashMap在eBPF中可以动态调整大小，这意味着它可以根据需要动态增长或缩小。这一点是通过在哈希表达到负载因子阈值时重新分配更大的存储空间来实现的。
- 在eBPF的内核代码中，HashMap的实现涉及到哈希函数的选择和哈希冲突的处理。
- 适合在运行时需要动态添加、删除键值对的场景。
- 适合快速查找特定键对应的值，复杂度为 O(1)。

接下来分析Hashmap的重要操作：查找和删除操作。

**1.1Hashmap的查找元素源码：(/kernel/bpf/hashtab.c)**

```c
/*
 * 函数: __htab_map_lookup_elem
 * ----------------------------
 * 此函数用于在 eBPF 程序或系统调用上下文中查找 HashTable Map 中的元素。
 * 根据提供的键查找并返回对应的元素。
 *
 * 参数:
 * - map: 指向 BPF map（bpf_map）基本结构的指针。
 * - key: 用于在 HashTable Map 中定位元素的键的指针。
 *
 * 返回:
 * - 成功时返回指向查找到的元素的指针；如果未找到则返回 NULL。
 */

static void *__htab_map_lookup_elem(struct bpf_map *map, void *key)
{
	struct bpf_htab *htab = container_of(map, struct bpf_htab, map);
	struct hlist_nulls_head *head;
	struct htab_elem *l;
	u32 hash, key_size;

	// 检查是否在 RCU 读取锁定期间执行
	WARN_ON_ONCE(!rcu_read_lock_held() && !rcu_read_lock_trace_held() &&
		     !rcu_read_lock_bh_held());

	key_size = map->key_size;  // 获取键的大小

	// 计算键的哈希值
	hash = htab_map_hash(key, key_size, htab->hashrnd);

	// 根据哈希值选择对应的桶
	head = select_bucket(htab, hash);

	// 在选定的桶中查找元素
	l = lookup_nulls_elem_raw(head, hash, key, key_size, htab->n_buckets);

	return l;  // 返回查找到的元素指针，如果未找到则返回 NULL
}
```

```c
static inline u32 htab_map_hash(const void *key, u32 key_len, u32 hashrnd)
{
	// 如果键的长度是 4 的倍数，使用 jhash2 计算哈希值
	if (likely(key_len % 4 == 0))
		return jhash2(key, key_len / 4, hashrnd);
	
	// 否则，使用 jhash 计算哈希值
	return jhash(key, key_len, hashrnd);
}
```

```c
/*
 * 函数: jhash
 * ------------
 * 哈希一个任意的键序列。
 * 参数:
 * - key: 作为键的字节序列的指针。
 * - length: 键的长度（以字节为单位）。
 * - initval: 先前的哈希值，或者一个任意的值作为初始哈希值。
 *
 * 返回:
 * - 键的哈希值。结果依赖于系统的字节序。
 *这段代码通过对输入的字节序列进行迭代处理，按照特定的算法（包括混合操作和最终化操作）计算出一个哈希值，用
 *于对任意数据进行快速的哈希映射。
 */
static inline u32 jhash(const void *key, u32 length, u32 initval)
{
	u32 a, b, c;
	const u8 *k = key;

	/* 设置内部状态 */
	a = b = c = JHASH_INITVAL + length + initval;

	/* 处理除最后一个块外的所有块：影响(a, b, c)的32位 */
	while (length > 12) {
		a += __get_unaligned_cpu32(k);       // 获取未对齐的32位整数
		b += __get_unaligned_cpu32(k + 4);   // 获取未对齐的32位整数
		c += __get_unaligned_cpu32(k + 8);   // 获取未对齐的32位整数
		__jhash_mix(a, b, c);                // 混合操作，影响哈希值
		length -= 12;                        // 减去处理的字节数
		k += 12;                             // 指针移动到下一个块
	}
	/* 最后一个块：影响(c)的所有32位 */
	/* 所有 case 语句都会顺序执行 */
	switch (length) {
	case 12: c += (u32)k[11]<<24;
	case 11: c += (u32)k[10]<<16;
	case 10: c += (u32)k[9]<<8;
	case 9:  c += k[8];
	case 8:  b += (u32)k[7]<<24;
	case 7:  b += (u32)k[6]<<16;
	case 6:  b += (u32)k[5]<<8;
	case 5:  b += k[4];
	case 4:  a += (u32)k[3]<<24;
	case 3:  a += (u32)k[2]<<16;
	case 2:  a += (u32)k[1]<<8;
	case 1:  a += k[0];
		 __jhash_final(a, b, c);  // 最终混合和收尾操作
	case 0:  /* 没有剩余的字节需要处理 */
		break;
	}

	return c;  // 返回计算得到的哈希值
}
```

**1.2Hashmap的删除元素源码：(/kernel/bpf/hashtab.c)**

```c
static long htab_lru_map_delete_elem(struct bpf_map *map, void *key)
{
    // 将 map 转换为包含它的 htab 结构体
	struct bpf_htab *htab = container_of(map, struct bpf_htab, map);
	
	// 定义一个指向 hlist_nulls_head 结构体的指针 head
	struct hlist_nulls_head *head;
	
	// 定义一个指向 bucket 结构体的指针 b
	struct bucket *b;
	
	// 定义一个指向 htab_elem 结构体的指针 l
	struct htab_elem *l;
	
	// 定义一个用于保存标志位的变量 flags
	unsigned long flags;
	
	// 定义一个无符号 32 位整数变量 hash 和 key_size
	u32 hash, key_size;
	
	// 定义一个整数变量 ret 用于保存返回值
	int ret;

	// 检查是否持有 RCU 读锁，如果没有则发出警告
	WARN_ON_ONCE(!rcu_read_lock_held() && !rcu_read_lock_trace_held() &&
		     !rcu_read_lock_bh_held());

	// 获取 map 的 key_size
	key_size = map->key_size;

	// 计算 key 的 hash 值
	hash = htab_map_hash(key, key_size, htab->hashrnd);
	
	// 根据 hash 值选择对应的桶
	b = __select_bucket(htab, hash);
	
	// 获取桶的头部指针
	head = &b->head;

	// 尝试锁定桶，返回值保存在 ret 中
	ret = htab_lock_bucket(htab, b, hash, &flags);
	
	// 如果锁定失败，则直接返回错误码
	if (ret)
		return ret;

	// 在桶中查找与key对应的元素
	l = lookup_elem_raw(head, hash, key, key_size);

	// 如果找到了元素，则从链表中删除该元素
	if (l)
		hlist_nulls_del_rcu(&l->hash_node);
	else
		// 如果没有找到元素，则设置返回值为 -ENOENT
		ret = -ENOENT;

	// 解锁桶
	htab_unlock_bucket(htab, b, hash, flags);
	
	// 如果找到了元素，则将其推送到 LRU free 列表
	if (l)
		htab_lru_push_free(htab, l);
	
	// 返回结果
	return ret;
}
```

```c
static inline void __hlist_nulls_del(struct hlist_nulls_node *n)
{
    // 获取当前节点的下一个节点
	struct hlist_nulls_node *next = n->next;
	
    // 获取指向当前节点前一个节点的指针
	struct hlist_nulls_node **pprev = n->pprev;

	// 使用 WRITE_ONCE 宏将当前节点的前一个节点的 next 指针指向当前节点的下一个节点
	WRITE_ONCE(*pprev, next);
	
	// 如果当前节点的下一个节点不是一个空节点
	if (!is_a_nulls(next))
		// 使用 WRITE_ONCE 宏将下一个节点的前一个节点的指针指向当前节点的前一个节点
		WRITE_ONCE(next->pprev, pprev);
}
```

### **2.BPF_MAP_TYPE_ARRAY**

- ArrayMap是一个数组，其中每个元素存储一个键值对。这种设计使得ArrayMap的存储顺序和插入顺序完全一致。
- ArrayMap在创建时需要指定最大大小，因为它的大小在运行时是不可变的。
- ArrayMap的实现比较简单，只需要一个数组和一个计数器。它的插入和查找操作都非常高效，因为它可以直接通过数组索引访问元素。
- 适合在运行时知道最大键值对数量的场景。
- 适合需要**按照插入顺序进行遍历**或处理的场景，因为它的元素存储顺序与插入顺序完全一致。

**2.1Arraymap的查找元素源码：(/kernel/bpf/arraymap.c)**

```c
static void *array_map_lookup_elem(struct bpf_map *map, void *key)
{
    /* 将基本的 BPF map 指针转换为特定的 BPF array map 结构 */
    struct bpf_array *array = container_of(map, struct bpf_array, map);
    
    /* 解引用键指针以获取索引 */
    u32 index = *(u32 *)key;
    
    /* 检查索引是否超出数组最大条目数 */
    if (unlikely(index >= array->map.max_entries))
        return NULL;
    
    /* 计算并返回元素地址 */
    return array->value + (u64)array->elem_size * (index & array->index_mask);
}
```

**2.2Arraymap的插入元素源码：(/kernel/bpf/arraymap.c)**

```c
static long array_map_update_elem(struct bpf_map *map, void *key, void *value,
				  u64 map_flags)
{
	struct bpf_array *array = container_of(map, struct bpf_array, map);
	u32 index = *(u32 *)key;  // 解引用键指针以获取索引
	char *val;
	// 检查是否存在未知标志位
	if (unlikely((map_flags & ~BPF_F_LOCK) > BPF_EXIST))
		return -EINVAL;
	// 检查索引是否超出最大条目数限制
	if (unlikely(index >= array->map.max_entries))
		return -E2BIG;
	// 检查是否禁止不存在元素的插入
	if (unlikely(map_flags & BPF_NOEXIST))
		return -EEXIST;
	// 如果要求使用锁定，并且未定义自旋锁字段，则返回错误
	if (unlikely((map_flags & BPF_F_LOCK) &&
		     !btf_record_has_field(map->record, BPF_SPIN_LOCK)))
		return -EINVAL;
	// 根据数组类型进行操作分支
	if (array->map.map_type == BPF_MAP_TYPE_PERCPU_ARRAY) {
		// 对于 BPF_MAP_TYPE_PERCPU_ARRAY 类型的数组
		val = this_cpu_ptr(array->pptrs[index & array->index_mask]);
		copy_map_value(map, val, value);  // 复制值到本地 CPU 的指定位置
		bpf_obj_free_fields(array->map.record, val);  // 释放对象字段
	} else {
		// 对于其他类型的数组
		val = array->value +
			(u64)array->elem_size * (index & array->index_mask);
		if (map_flags & BPF_F_LOCK)
			copy_map_value_locked(map, val, value, false);  // 锁定状态下复制值
		else
			copy_map_value(map, val, value);  // 非锁定状态下复制值
		bpf_obj_free_fields(array->map.record, val);  // 释放对象字段
	}
	return 0;  // 操作成功返回 0
}
```

**2.3AraayMap删除元素：(/kernel/bpf/arraymap.c)**

```c
/*
 * 此函数用于在 eBPF 程序或系统调用上下文中删除 ArrayMap 中的元素。
 * 根据提供的键删除 ArrayMap 中的元素，并释放相关资源。
 */

static long fd_array_map_delete_elem(struct bpf_map *map, void *key)
{
	struct bpf_array *array = container_of(map, struct bpf_array, map);
	void *old_ptr;
	u32 index = *(u32 *)key;

	// 检查索引是否超出最大条目数限制
	if (index >= array->map.max_entries)
		return -E2BIG;

	// 如果 map_poke_run 操作存在，则使用 mutex 锁定并执行相关操作
    //当执行特定的 map 操作时（如更新或删除元素），如果该操作涉及到需要额外的处理或者通知机制，就会调用 	  //map_poke_run 函数来完成这些额外的任务。
	if (map->ops->map_poke_run) {
		mutex_lock(&array->aux->poke_mutex);
		old_ptr = xchg(array->ptrs + index, NULL);
		map->ops->map_poke_run(map, index, old_ptr, NULL);
		mutex_unlock(&array->aux->poke_mutex);
	} else {
		// 否则直接执行元素交换操作
		old_ptr = xchg(array->ptrs + index, NULL);
	}

	// 如果成功删除元素，则释放相关资源
	if (old_ptr) {
        //在 eBPF 中，文件描述符通常用于操作与内核资源相关的对象，如 bpf_map 中的数据结构。当不再需要
        //这些资源时，就需要调用 map_fd_put_ptr 函数指针所指向的函数，来释放相关的资源或执行清理操作，
        //以避免资源泄漏或者内存泄漏问题。
		map->ops->map_fd_put_ptr(old_ptr);
		return 0;
	} else {
		// 如果元素不存在，则返回错误码 -ENOENT
		return -ENOENT;
	}
}
```

### 3.BPF_MAP_TYPE_PERCPU_HASH

- **Per-CPU Hash Map** 是一种哈希表，其中每个 CPU 都有自己**独立的哈希表副本**。这种设计使得在多核环境下访问哈希表时可以**避免锁争用**，从而提高并发性能。
- 每个哈希表副本在创建时并不需要指定最大大小，因此其大小可以根据需要动态增长。
- **Per-CPU Hash Map** 的实现相对复杂，因为它需要管理多个哈希表副本，并在访问时根据当前 CPU 进行相应的查找或更新操作。
- 适合**需要高并发读写**的场景，尤其是在多核系统中，因为每个 CPU 的操作都是独立的，不会因为其他 CPU 的操作而产生竞争。
- 适合**按需动态调整大小**的场景，因为它不像数组那样需要预定义大小。

**3.1per-cpu hash的查找操作源码：(/kernel/bpf/hashtab.c)**

```c
static void *htab_percpu_map_lookup_elem(struct bpf_map *map, void *key)
{
    // 通过键在哈希表中查找对应的哈希表元素,此方法和普通的hash表查找操作相同
    struct htab_elem *l = __htab_map_lookup_elem(map, key);

    // 如果找到元素 l，此时的l若不为空，则l代表查到了每个cpu的数据副本
    if (l)
        // 获取当前 CPU 上对应的数据副本并返回
        return this_cpu_ptr(htab_elem_get_ptr(l, map->key_size));
    else
        // 如果没有找到元素，返回 NULL
        return NULL;
}
```

接下来查看htab_elem_get_ptr（）函数：

```c
static inline void __percpu *htab_elem_get_ptr(struct htab_elem *l, u32 key_size)
{
    // 返回指向 per-CPU 数据的指针
    // 计算元素 l 中数据的存储位置，跳过键（key）后的空间，获取 per-CPU 数据的指针
    return *(void __percpu **)(l->key + key_size);
}
```

该函数的作用是从哈希表元素 `l` 中获取指向 per-CPU 数据的指针。哈希表元素 `l` 中存储了键值对，而键的大小由 `key_size` 决定,`l->key` 是指向键的指针，因此 `l->key + key_size` 表示跳过键后，定位到 per-CPU 数据存储的起始位置。`l->key + key_size`: 从 `l` 结构体中的 `key` 开始，偏移 `key_size` 个字节后到达数据区域。`*(void __percpu **)(...)`: 将偏移后的地址解释为一个 `void __percpu *` 类型的指针，并返回该指针。

`htab_elem_get_ptr()` 返回的是一个 **per-CPU 数据区域的基地址**，即包含了所有 CPU 的数据。

`this_cpu_ptr()` 使用当前 CPU 的 ID，从这个基地址中 **获取当前 CPU 的数据副本**。

**3.2per-cpu hash的创建源码：(/kernel/bpf/memalloc.c)**

```c
/*
 * 初始化 BPF 内存分配器
 *
 * @ma: 指向 bpf_mem_alloc 结构的指针，负责管理内存分配
 * @size: 每个内存块的大小。如果 size 不为 0，则表示所有分配的元素具有相同的大小
 * @percpu: 如果为 true，则为每个 CPU 分配独立的内存
 *
 * 返回值: 0 表示成功，负数表示分配失败或参数错误
 */
int bpf_mem_alloc_init(struct bpf_mem_alloc *ma, int size, bool percpu)
{
    // 内存池支持的缓存大小，NUM_CACHES 是缓存数量
    static u16 sizes[NUM_CACHES] = {96, 192, 16, 32, 64, 128, 256, 512, 1024, 2048, 4096};
    
    struct bpf_mem_caches *cc, __percpu *pcc;
    struct bpf_mem_cache *c, __percpu *pc;
    struct obj_cgroup *objcg = NULL;
    int cpu, i, unit_size, percpu_size = 0;

    // 标记是否为 per-cpu 分配
    ma->percpu = percpu;

    // 如果 size 不为 0，表示所有元素大小相同，执行此分支
    if (size) {
        // 为每个 CPU 分配一个 bpf_mem_cache 结构的 per-cpu 存储空间
        pc = __alloc_percpu_gfp(sizeof(*pc), 8, GFP_KERNEL);
        if (!pc)
            return -ENOMEM;  // 分配失败，返回内存不足错误

        // 如果是 per-cpu 模式，计算 per-cpu 内存大小，包含链表节点和指针
        if (percpu)
            percpu_size = LLIST_NODE_SZ + sizeof(void *);
        else
            size += LLIST_NODE_SZ;  // 非 per-cpu 模式，只需为链表节点预留空间

        unit_size = size;

#ifdef CONFIG_MEMCG_KMEM
        // 如果内存控制组（memory cgroup）启用，从当前任务获取对象控制组
        if (memcg_bpf_enabled())
            objcg = get_obj_cgroup_from_current();
#endif

        // 为系统中所有可能的 CPU 分配内存，并初始化相关数据结构
        for_each_possible_cpu(cpu) {
            c = per_cpu_ptr(pc, cpu);  // 获取当前 CPU 的内存缓存指针
            c->unit_size = unit_size;  // 设置内存块大小
            c->objcg = objcg;          // 关联对象控制组
            c->percpu_size = percpu_size;  // 设置 per-cpu 内存大小
            c->tgt = c;                // 目标指针指向自身

            // 初始化缓存的 refill 工作，并填充缓存
            init_refill_work(c);
            prefill_mem_cache(c, cpu);
        }

        ma->cache = pc;  // 保存分配的 per-cpu 缓存
        return 0;  // 分配成功，返回 0
    }

    // 如果 size == 0 并且 percpu 为 true，这是无效的组合
    if (WARN_ON_ONCE(percpu))
        return -EINVAL;  // 返回无效参数错误

    // 为每个 CPU 分配多个大小的缓存（对应 sizes 数组）
    pcc = __alloc_percpu_gfp(sizeof(*cc), 8, GFP_KERNEL);
    if (!pcc)
        return -ENOMEM;  // 分配失败，返回内存不足错误

#ifdef CONFIG_MEMCG_KMEM
    // 获取当前任务的对象控制组
    objcg = get_obj_cgroup_from_current();
#endif

    // 为所有可能的 CPU 分配缓存，并初始化
    for_each_possible_cpu(cpu) {
        cc = per_cpu_ptr(pcc, cpu);  // 获取当前 CPU 的内存缓存指针
        for (i = 0; i < NUM_CACHES; i++) {
            c = &cc->cache[i];  // 获取每个缓存的指针
            c->unit_size = sizes[i];  // 设置缓存的大小
            c->objcg = objcg;         // 关联对象控制组
            c->tgt = c;               // 目标指针指向自身

            // 初始化缓存的 refill 工作，并填充缓存
            init_refill_work(c);
            prefill_mem_cache(c, cpu);
        }
    }

    ma->caches = pcc;  // 保存分配的 per-cpu 缓存
    return 0;  // 分配成功，返回 0
}
```

### 4.BPF_MAP_TYPE_PERCPU_ARRAY

- **Per-CPU Array Map** 是一种数组，每个 CPU 都有自己独立的数组副本。每个数组中的元素存储一个键值对，且所有 CPU 的数组结构是相同的。
- 与普通的 Array Map 类似，**Per-CPU Array Map** 也需要在创建时指定最大大小，因为数组的大小在运行时是不可变的。
- **Per-CPU Array Map** 的实现相对简单，可以通过数组索引直接访问元素，因此插入和查找操作都非常高效。
- 适合**需要高并发读写且按索引访问**的场景，尤其是在多核系统中，因为每个 CPU 的数组操作都是独立的。
- 适合**在运行时已知最大键值对数量**的场景，因为它在创建时需要指定数组的最大大小。

**4.1per-cpu-array的创建源码：（/kernel/bpf/arraymap.c）**

```c
static int bpf_array_alloc_percpu(struct bpf_array *array)
{
	// 用于存储 per-cpu 分配的指针
	void __percpu *ptr;
	int i;

	// 遍历每个数组条目，为每个条目分配 per-cpu 的内存
	for (i = 0; i < array->map.max_entries; i++) {
		// 调用 bpf_map_alloc_percpu 为当前数组条目分配 per-cpu 内存
		ptr = bpf_map_alloc_percpu(&array->map, array->elem_size, 8,
					   GFP_USER | __GFP_NOWARN);
		if (!ptr) {
			// 如果分配失败，释放之前已分配的 per-cpu 内存
			bpf_array_free_percpu(array);
			return -ENOMEM;  // 返回内存分配失败错误
		}
		// 将分配的 per-cpu 内存指针存储到数组的 pptrs（per-cpu 指针数组）中
		array->pptrs[i] = ptr;
		
		// 在分配过程中调用 cond_resched，以便让内核有机会调度其他任务
		cond_resched();
	}

	// 所有数组条目成功分配 per-cpu 内存后，返回 0，表示成功
	return 0;
}
```

该函数负责为 `BPF_MAP_TYPE_PERCPU_ARRAY` 类型的 BPF 数组的每个元素分配独立的 per-cpu 内存。循环遍历每个数组元素，调用 `bpf_map_alloc_percpu` 为每个元素分配 per-cpu 内存，将分配的 per-cpu 内存指针存储到 `array->pptrs` 中，方便后续使用。该函数的目标是确保 `BPF_MAP_TYPE_PERCPU_ARRAY` 的每个条目都拥有独立的 per-cpu 内存空间，以便在多 CPU 环境中高效处理数据。

**4.2per-cpu-array的查找源码：（/kernel/bpf/arraymap.c）**

```c
static void *percpu_array_map_lookup_elem(struct bpf_map *map, void *key)
{
	// 将 bpf_map 结构体转换为 bpf_array 结构体，以便访问数组特有的字段
	struct bpf_array *array = container_of(map, struct bpf_array, map);
	// 将 key 转换为 u32 类型，作为数组的索引
	u32 index = *(u32 *)key;

	// 检查索引是否超出数组的最大有效索引范围
	if (unlikely(index >= array->map.max_entries))
		return NULL;

	// 使用 this_cpu_ptr 宏获取当前 CPU 上的值
	// array->pptrs 存储每个索引的 per-cpu 指针
	// 通过 index & array->index_mask 确保索引在有效范围内
	return this_cpu_ptr(array->pptrs[index & array->index_mask]);
}
```

### 5.BPF_MAP_TYPE_RINGBUF

- **Ring Buffer Map** 是一种先进先出（FIFO）环形缓冲区，设计用于存储和管理动态生成的数据。**Ring Buffer Map** 允许用户在内核空间和用户空间之间进行高效的数据传输，尤其适合处理大量实时数据。
- **Ring Buffer Map** 的大小在创建时需要指定，且要求该大小是 2 的幂次方并且页面对齐。其大小在运行时是固定的，不能动态调整。
- **Ring Buffer Map** 的实现基于环形缓冲区结构，数据插入和读取操作遵循先进先出的原则。由于其设计允许重用缓冲区中的空间，因此可以有效地管理内存。
- 适合**需要高效数据流传输和处理**的场景，尤其是在需要频繁写入和读取数据的高性能应用中，如网络数据包捕获和性能监控。
- 适合**需要稳定和高效的循环缓冲区管理**的场景，因为**Ring Buffer Map** 可以高效地处理持续不断的数据流，同时避免了传统缓冲区的空间浪费问题。

**5.1 ring-buff的创建源码：（/kernel/bpf/ringbuf.c）**

```c
static struct bpf_map *ringbuf_map_alloc(union bpf_attr *attr)
{
    struct bpf_ringbuf_map *rb_map;

    // 检查属性标志是否有效，确保没有使用不支持的标志位
    if (attr->map_flags & ~RINGBUF_CREATE_FLAG_MASK)
        return ERR_PTR(-EINVAL);

    // 检查 key_size 和 value_size 是否为零，最大条目数是否为 2 的幂，并且是否与页面对齐
    if (attr->key_size || attr->value_size ||
        !is_power_of_2(attr->max_entries) ||
        !PAGE_ALIGNED(attr->max_entries))
        return ERR_PTR(-EINVAL);

    // 分配 bpf_ringbuf_map 结构体的内存
    rb_map = bpf_map_area_alloc(sizeof(*rb_map), NUMA_NO_NODE);
    if (!rb_map)
        return ERR_PTR(-ENOMEM);

    // 根据属性初始化 BPF map
    bpf_map_init_from_attr(&rb_map->map, attr);

    // 分配 ring buffer 的内存
    rb_map->rb = bpf_ringbuf_alloc(attr->max_entries, rb_map->map.numa_node);
    if (!rb_map->rb) {
        // 如果分配失败，释放之前分配的内存
        bpf_map_area_free(rb_map);
        return ERR_PTR(-ENOMEM);
    }

    // 返回初始化后的 BPF map
    return &rb_map->map;
}
```

接下来再查看bpf_ringbuf_alloc（）函数是如何分配ring buffer 内存的。

```c
static struct bpf_ringbuf *bpf_ringbuf_area_alloc(size_t data_sz, int numa_node)
{
	const gfp_t flags = GFP_KERNEL_ACCOUNT | __GFP_RETRY_MAYFAIL |
			    __GFP_NOWARN | __GFP_ZERO;
	int nr_meta_pages = RINGBUF_NR_META_PAGES; // 元数据页面的数量
	int nr_data_pages = data_sz >> PAGE_SHIFT; // 数据页面的数量
	int nr_pages = nr_meta_pages + nr_data_pages; // 总页面数量
	struct page **pages, *page;
	struct bpf_ringbuf *rb;
	size_t array_size;
	int i;

	/* 每个数据页被映射两次，以允许对环形缓冲区中
	 * 尾部环绕的样本进行“虚拟”连续读取：
	 * ------------------------------------------------------
	 * | 元数据页面 |  实际的数据页面  |  相同的数据页面  |
	 * ------------------------------------------------------
	 * |            | 1 2 3 4 5 6 7 8 9 | 1 2 3 4 5 6 7 8 9 |
	 * ------------------------------------------------------
	 * |            | TA             DA | TA             DA |
	 * ------------------------------------------------------
	 *                               ^^^^^^^
	 *                                  |
	 * 由于双重映射数据页，这里不需要担心环绕数据的特殊处理。
	 * 这在内核和用户空间 mmap() 时均有效，显著简化了
	 * 内核和用户空间的实现。
	 */
	array_size = (nr_meta_pages + 2 * nr_data_pages) * sizeof(*pages); // 计算页面数组大小，包括元数据和双重映射的数据页
	pages = bpf_map_area_alloc(array_size, numa_node); // 为页面数组分配内存
	if (!pages)
		return NULL; // 如果分配页面数组失败，则返回 NULL

	// 为所有页面分配物理内存
	for (i = 0; i < nr_pages; i++) {
		page = alloc_pages_node(numa_node, flags, 0); // 分配单个页面
		if (!page) {
			nr_pages = i; // 更新成功分配的页面数量
			goto err_free_pages; // 如果分配失败，释放已分配的页面
		}
		pages[i] = page; // 将页面存储到页面数组中
		// 为环形缓冲区分配双重映射的页面
		if (i >= nr_meta_pages)
			pages[nr_data_pages + i] = page; // 将相同的数据页进行双重映射
	}

	// 将所有页面映射到内核虚拟地址空间
	rb = vmap(pages, nr_meta_pages + 2 * nr_data_pages,
		  VM_MAP | VM_USERMAP, PAGE_KERNEL); // 将元数据页和数据页映射到虚拟内存
	if (rb) {
		kmemleak_not_leak(pages); // 告诉内存泄漏探测器忽略这些页面
		rb->pages = pages; // 保存页面数组指针
		rb->nr_pages = nr_pages; // 保存总页面数量
		return rb; // 返回已分配和映射的环形缓冲区
	}

err_free_pages:
	// 如果发生错误，释放已分配的页面
	for (i = 0; i < nr_pages; i++)
		__free_page(pages[i]); // 释放页面
	bpf_map_area_free(pages); // 释放页面数组内存
	return NULL; // 返回 NULL，表示环形缓冲区分配失败
}
```

这里需要来说明一下为什么要进行双重映射：

这里我们举一个例子：假设我们有一个环形缓冲区，总大小为 **8 页**，每页大小为 **1KB**。为了简化说明，假设缓冲区的虚拟地址从 **0x1000** 开始。双重映射后的内存布局：

```c
物理内存（假设物理地址）：
[Page 0][Page 1][Page 2][Page 3][Page 4][Page 5][Page 6][Page 7]
虚拟地址空间：
[0x1000-0x13FF] -> Page 0
[0x1400-0x17FF] -> Page 1
...
[0x1C00-0x1FFF] -> Page 7
[0x2000-0x23FF] -> Page 0  (再次映射 Page 0)
[0x2400-0x27FF] -> Page 1  (再次映射 Page 1)
...
[0x2C00-0x2FFF] -> Page 7  (再次映射 Page 7)

```

**写入数据：**写入指针（head）从 **0x1000** 开始，依次写入 Page 0 到 Page 7。当写入指针到达 Page 7 后，再次回绕到 Page 0。

**读取数据**：假设当前写入指针在 **Page 2**，读取指针在 **Page 6**。读取指针位于 **Page 6**，需要读取从 **Page 6** 到 **Page 2** 的数据。在物理内存中，这些数据分布在 Page 6、Page 7 和回绕到 Page 0、Page 1、Page 2。但由于每个页面被映射了两次，读取指针在虚拟地址空间中可以连续读取：从 **0x1C00-0x1FFF** (Page 7) 继续读取到 **0x2000-0x23FF** (Page 0)。这样，读取过程在虚拟地址空间中是连续的，无需处理跨页边界的逻辑。

**优点：**开发者或内核在读取数据时，可以像处理一个线性内存块一样连续读取，即使数据在物理内存中实际上是分开的。避免了在读取数据时需要检查是否跨越缓冲区边界，从而减少了额外的条件判断和可能的性能开销。

## 二、理论分析结果：

### **1. BPF_MAP_TYPE_HASH**

##### **特点：**

- **数据结构**：基于哈希表实现，每个键值对通过哈希函数来确定其在表中的位置。
- **查找效率**：通常具有常数时间复杂度（O(1)）用于插入、查找和删除操作，但在哈希冲突严重时，性能可能下降。
- **键值对**：键（key）和值（value）的数据类型可以不同，但键必须是可哈希的。
- **内存使用**：由于哈希表需要存储哈希桶和链表（或其他结构），内存使用可能较高。

##### **适用场景：**

- **动态键值对**：适合用于存储和检索动态的键值对，尤其是当键的范围不固定或不可预测时。
- **频繁查找**：当需要快速查找、更新和删除操作时，hashmap 是理想的选择。
- **数据稀疏**：适用于数据稀疏且键值对不连续的场景，例如，跟踪网络流量中的源IP和目的IP。

### 2. **BPF_MAP_TYPE_ARRAY**

##### **特点：**

- **数据结构**：基于数组实现，所有的键是整数索引，值是与索引对应的数据。
- **查找效率**：具有常数时间复杂度（O(1)）用于插入、查找和删除操作，因索引可以直接映射到数组位置。
- **键值对**：键必须是整数索引，通常从0开始，并且连续。值可以是任意类型，但数组的大小必须在创建时定义。
- **内存使用**：由于使用数组，内存使用较为稳定，不受哈希表可能导致的内存碎片影响。

##### **适用场景：**

- **固定范围键**：适合用于存储键为连续整数索引的场景，例如，跟踪数组中每个位置的状态。
- **简单索引**：当键是已知的、有限范围的整数时，arraymap 是更高效的选择。
- **性能稳定**：在内存使用和性能上都较为稳定，适合用于固定大小的配置数据或状态跟踪。

### 3.BPF_MAP_TYPE_PERCPU_HASH

##### **特点：**

- **数据结构**：基于哈希表实现，每个 CPU 都有独立的哈希表副本，键可以是任意类型（如整数、结构体），而值则存储在每个 CPU 上独立的哈希表中。
- **查找效率**：插入、查找和删除操作的时间复杂度通常为 O(1)，但是会根据哈希冲突情况有所不同。
- **键值对**：键可以是任意类型，值在每个 CPU 上有独立的副本。每个 CPU 的哈希表是相互独立的，避免了多核之间的锁竞争。
- **内存使用**：由于每个 CPU 都有独立的哈希表副本，内存消耗与 CPU 数量成正比。适合多核场景下的并行读写操作。

##### **适用场景：**

- **高并发场景**：适合多核系统中并发读写操作的场景，如跟踪每个 CPU 独立的数据统计（例如每个 CPU 的网络包计数）。
- **读写分离**：当数据操作可以分散到每个 CPU 上进行独立处理，减少锁竞争时，`percpu_hash` 是理想选择。
- **动态键**：适用于键是动态生成的、不固定的场景，尤其在每个 CPU 都需要独立存储和读取数据的情况下。

### 4.BPF_MAP_TYPE_PERCPU_ARRAY

##### **特点：**

- **数据结构**：基于数组实现，每个 CPU 都有自己独立的数组副本。数组中的元素存储键值对，所有 CPU 的数组结构相同。
- **查找效率**：常数时间复杂度（O(1)）的插入、查找和删除操作，通过数组索引直接访问元素。
- **键值对**：键必须是整数索引，且所有 CPU 的数组在创建时大小固定。值在每个 CPU 上有独立的副本，支持并行操作。
- **内存使用**：内存消耗较为稳定，每个 CPU 都有自己的数组副本，因此内存开销与 CPU 数量和数组大小成正比。

##### **适用场景：**

- **高并发读写**：适合多核系统中频繁读写、按索引访问的场景。每个 CPU 独立操作各自的数组，避免了跨 CPU 的锁竞争。
- **已知大小的索引访问**：适用于数组大小在创建时已知、键是有限范围的场景，例如在多核系统中统计数据或跟踪状态。
- **性能稳定**：适合需要高效索引访问，并且对性能稳定性有要求的场景。

### 5.BPF_MAP_TYPE_RINGBUF

##### **特点：**

- **数据结构**：基于环形缓冲区（ring buffer）实现，支持用户空间和内核空间之间的数据传输。它使用双映射（双重页映射）来实现高效的数据读取，避免缓冲区溢出时复杂的处理逻辑。
- **查找效率**：采用生产者-消费者模式，生产者（通常是内核）将数据写入缓冲区，消费者（如用户空间程序）通过轮询或通知的方式读取数据。缓冲区满时，生产者会暂停写入。
- **键值对**：没有显式的键值对概念，而是按照数据的写入顺序读取。适合顺序写入和读取的大量数据场景。
- **内存使用**：内存使用量根据环形缓冲区的大小和页数固定。双重页映射机制允许读取者访问连续数据，即使数据跨越缓冲区边界。

##### **适用场景：**

- **高效数据传输**：适合高吞吐量的数据传输场景，尤其是从内核空间向用户空间传输大量数据的场景，如网络包捕获或性能数据收集。
- **顺序写入读取**：适合连续写入和读取数据的场景，不适合随机访问。读写操作之间严格遵循生产者-消费者模式。
- **性能敏感场景**：适用于需要低延迟、高效数据传输的场景，特别是在需要频繁从内核向用户空间传递信息时。
