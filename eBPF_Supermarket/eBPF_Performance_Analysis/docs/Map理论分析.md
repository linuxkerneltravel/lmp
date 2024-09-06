# Hashmap和Arraymap对比测试

测试之前，先对hashmap和arraymap进行理论上的分析：

## 一、理论分析

**HashMap：**

- 在eBPF中，HashMap实际上是一个哈希表，用于将键映射到值。它使用哈希函数来计算键的哈希值，并将其映射到一个存储桶（bucket）中。
- 哈希表内部由一个数组（buckets）和链表（或者是红黑树）组成。数组中的每个元素是一个链表头或树的根节点，用于处理哈希冲突。
- HashMap在eBPF中可以动态调整大小，这意味着它可以根据需要动态增长或缩小。这一点是通过在哈希表达到负载因子阈值时重新分配更大的存储空间来实现的。
- 在eBPF的内核代码中，HashMap的实现涉及到哈希函数的选择和哈希冲突的处理。
- 适合在运行时需要动态添加、删除键值对的场景。
- 适合快速查找特定键对应的值，复杂度为 O(1)。

**1.Hashmap的查找元素源码：(/kernel/bpf/hashtab.c)**

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
 *
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

**2.Hashmap的查找元素源码：(/kernel/bpf/hashtab.c)**

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

	// 在桶中查找与 key 对应的元素
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

**Arraymap：**

- ArrayMap是一个数组，其中每个元素存储一个键值对。这种设计使得ArrayMap的存储顺序和插入顺序完全一致。
- ArrayMap在创建时需要指定最大大小，因为它的大小在运行时是不可变的。
- ArrayMap的实现比较简单，只需要一个数组和一个计数器。它的插入和查找操作都非常高效，因为它可以直接通过数组索引访问元素。
- 适合在运行时知道最大键值对数量的场景。
- 适合需要按照插入顺序进行遍历或处理的场景，因为它的元素存储顺序与插入顺序完全一致。

**1.Arraymap的查找元素源码：(/kernel/bpf/arraymap.c)**

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

**2.Arraymap的插入元素源码：(/kernel/bpf/arraymap.c)**

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

**3.AraayMap删除元素：(/kernel/bpf/arraymap.c)**

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

## 二、理论分析结果：

#### **1. Hash Map (`hashmap`)**

##### **特点：**

- **数据结构**：基于哈希表实现，每个键值对通过哈希函数来确定其在表中的位置。
- **查找效率**：通常具有常数时间复杂度（O(1)）用于插入、查找和删除操作，但在哈希冲突严重时，性能可能下降。
- **键值对**：键（key）和值（value）的数据类型可以不同，但键必须是可哈希的。
- **内存使用**：由于哈希表需要存储哈希桶和链表（或其他结构），内存使用可能较高。

#### **适用场景：**

- **动态键值对**：适合用于存储和检索动态的键值对，尤其是当键的范围不固定或不可预测时。
- **频繁查找**：当需要快速查找、更新和删除操作时，hashmap 是理想的选择。
- **数据稀疏**：适用于数据稀疏且键值对不连续的场景，例如，跟踪网络流量中的源IP和目的IP。

#### 2. **Array Map (`arraymap`)**

##### **特点：**

- **数据结构**：基于数组实现，所有的键是整数索引，值是与索引对应的数据。
- **查找效率**：具有常数时间复杂度（O(1)）用于插入、查找和删除操作，因索引可以直接映射到数组位置。
- **键值对**：键必须是整数索引，通常从0开始，并且连续。值可以是任意类型，但数组的大小必须在创建时定义。
- **内存使用**：由于使用数组，内存使用较为稳定，不受哈希表可能导致的内存碎片影响。

#### **适用场景：**

- **固定范围键**：适合用于存储键为连续整数索引的场景，例如，跟踪数组中每个位置的状态。
- **简单索引**：当键是已知的、有限范围的整数时，arraymap 是更高效的选择。
- **性能稳定**：在内存使用和性能上都较为稳定，适合用于固定大小的配置数据或状态跟踪。

#### 3.**总结：**

- **Hash Map**：
  - **优点**：灵活，适用于动态和不规则的数据。
  - **缺点**：可能需要处理哈希冲突，内存使用可能不如 arraymap 稳定。
  - **适用场景**：复杂的键值对数据，动态范围的数据。
- **Array Map**：
  - **优点**：高效、内存使用稳定，适合固定范围的整数键。
  - **缺点**：不适用于键范围不固定的场景。
  - **适用场景**：需要高效、固定范围的索引数据。

#### 4.**选择指南：**

- 如果你的应用场景需要处理复杂的键值对，并且键是动态或不连续的，`hashmap` 是更合适的选择。
- 如果你有一个固定范围的、连续的整数索引，并且希望获得最稳定的性能和内存使用，`arraymap` 是更适合的选择。
