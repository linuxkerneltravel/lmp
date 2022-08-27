## iostat原理简析
iostat命令实际是读取/proc/diskstats获取的IO数据，然后计算IO使用率等数据，对应的内核函数是diskstats_show()。

### 底层数据项
- hd_struct：描述一个具体的磁盘分区
```c
//位置：include/linux/genhd.h
struct hd_struct {
	sector_t start_sect;    //起始扇区号
	sector_t nr_sects;      //扇区个数
	seqcount_t nr_sects_seq;    
	sector_t alignment_offset;
	unsigned int discard_alignment;
	struct device __dev;
	struct kobject *holder_dir;
	int policy, partno;
	struct partition_meta_info *info;
#ifdef CONFIG_FAIL_MAKE_REQUEST
	int make_it_fail;
#endif
	unsigned long stamp;    //当前系统时间jiffies
	atomic_t in_flight[2];  //表示IO队列中读写请求个数
#ifdef	CONFIG_SMP
	struct disk_stats __percpu *dkstats;    //记录IO使用率等原始数据
#else
	struct disk_stats dkstats;
#endif
	struct percpu_ref ref;
	struct rcu_head rcu_head;
};
```

其中最关键的成员是*dkstats，iostat很多需要展示的数据就是从这里提取的。disk_stats结构如下所示：
```c
struct disk_stats {
	unsigned long sectors[2];	//读写扇区总数
	unsigned long ios[2];       //完成的IO个数
	unsigned long merges[2];    //合并的IO个数（电梯调度算法把多个属性相同的IO请求合并为一个）
	unsigned long ticks[2];
	unsigned long io_ticks;
	unsigned long time_in_queue;  //IO在队列中的时间
};
```

下边列举一下块设备IO使用率有关的几个统计项数据：
- in_flight[]
  表示已经提交IO到队列但是还没有传输完成的IO个数，也就是IO队列中的个数+已发送到磁盘驱动但是还未传输完成的个数。
  新分配的request加入IO队列，in_flight加1；
  当一个request传输完成，in_flight减1。

- io_ticks
  单位时间内已经提交IO到队列但是还没有传输完成的IO花费的时间，它与in_flight紧密相关。
  如果1s内，有800ms in_flight都大于0，说明”单位时间内已经提交IO到队列但是还没有传输完成的IO花费的时间”是800ms，则该段时间的IO使用率就是80%。
  IO使用率就是这样来计算的。

- sectors：
  表示当前块设备的request传输完成的扇区数，累加值。
  更新流程是blk_account_io_completion->part_stat_add。
  实际上一个request代表的总扇区数一次传输并不能传输完，会产生好几次中断，每次中断后的软中断都会执行到blk_account_io_completion()，然后累计一下当前完成传输的扇区数。

- ios
  ios表示当前块设备传输完成的request个数，累加值。
  只有request所在的扇区数全部传输完，执行blk_account_io_done->part_stat_inc令ios累加1。

- merges
  表示当前块设备bio合并到进程plug链表的request或者IO算法队列的request的个数。

- ticks
  累计该块设备的所有的request传输耗时。
  在req分配时会记录当前系统时间jiffies（req->start_time=jiffies），然后等request对应的磁盘数据全部传输完（duration= jiffies - req->start_time），duration则是该request传输耗时，然后把这个request传输耗时累加到ticks。

- time_in_queue
  表示当前块设备的IO队列中的总IO数在IO队列中的时间，更新流程是：part_round_stats->part_round_stats_single->__part_stat_add(cpu,part,time_in_queue,part_in_flight(part)*(now-part->stamp))

- part->stamp
  当前系统启动时间，可以用来当作函数的检查项。

### /proc/diskstats
内核很多重要子系统均通过proc文件的方式，将自身的一些统计信息输出，方便最终用户查看各子系统的运行状态，这些统计信息被称为metrics。 直接查看metrics并不能获取到有用的信息，一般都是由特定的应用程序(htop/sar/iostat等)每隔一段时间读取相关metrics，并进行相应计算，给出更具用户可读性的输出。 常见的metrics文件有：
• cpu调度统计信息的/proc/stat
• cpu负载统计信息的/proc/loadavg
通用块设备层也有一个重要的统计信息
• /proc/diskstats内核通过diskstats文件，将通用块设备层的一些重要指标以文件的形式呈现给用户
以该文件中的一行为例：
```
8       1 sda1 159 0 9916 304 11 2 68 28 0 292 332
```
该内核文档解释了它们的含义https://www.kernel.org/doc/Documentation/iostats.txt
-  (rd_ios)读操作的次数。
-  (rd_merges)合并读操作的次数
-  (rd_sectors)读取的扇区数量。
-  (rd_ticks)读操作消耗的时间（以毫秒为单位）
-  (wr_ios)写操作的次数。
-  (wr_merges)合并写操作的次数。
-  (wr_sectors)写入的扇区数量
-  (wr_ticks)写操作消耗的时间（以毫秒为单位）
-  (in_flight)当前未完成的I/O数量
-  (io_ticks)该设备用于处理I/O的自然时间
-  (time_in_queue)io_ticks的加权值
  是用当前的I/O数量（即字段#9 in-flight）乘以自然时间(字段#10 io_ticks)。

现在以上述行为例注明一下：
- F1    8	    major number	此块设备的主设备号
- F2    1	    minor mumber	此块设备的次设备号
- F3    sda1	device name	    此块设备名字
- F4    159   读操作的次数
- F5    0     读请求合并的次数
- F6    9916  读取扇区数
- F7    304   读操作耗费时间
- F8    11    写操作次数
- F9    2     写请求合并次数
- F10   68    写入扇区数
- F11   28    写操作耗费时间
- F12   0     当前未完成IO数
- F13   292   用于处理IO的自然时间
- F14   332   加权时间

### diskstats_show函数
```c
static int diskstats_show(struct seq_file *seqf, void *v)
{
	struct gendisk *gp = v;
	struct disk_part_iter piter;
	struct hd_struct *hd;
	char buf[BDEVNAME_SIZE];
	unsigned int inflight[2];
	int cpu;

	/*
	if (&disk_to_dev(gp)->kobj.entry == block_class.devices.next)
		seq_puts(seqf,	"major minor name"
				"     rio rmerge rsect ruse wio wmerge "
				"wsect wuse running use aveq"
				"\n\n");
	*/

	disk_part_iter_init(&piter, gp, DISK_PITER_INCL_EMPTY_PART0);
	while ((hd = disk_part_iter_next(&piter))) {
		cpu = part_stat_lock();
		part_round_stats(gp->queue, cpu, hd);
		part_stat_unlock();
		part_in_flight(gp->queue, hd, inflight);
		seq_printf(seqf, "%4d %7d %s %lu %lu %lu "
			   "%u %lu %lu %lu %u %u %u %u\n",
			   MAJOR(part_devt(hd)), MINOR(part_devt(hd)),
			   disk_name(gp, hd->partno, buf),
			   part_stat_read(hd, ios[READ]),
			   part_stat_read(hd, merges[READ]),
			   part_stat_read(hd, sectors[READ]),
			   jiffies_to_msecs(part_stat_read(hd, ticks[READ])),
			   part_stat_read(hd, ios[WRITE]),
			   part_stat_read(hd, merges[WRITE]),
			   part_stat_read(hd, sectors[WRITE]),
			   jiffies_to_msecs(part_stat_read(hd, ticks[WRITE])),
			   inflight[0],
			   jiffies_to_msecs(part_stat_read(hd, io_ticks)),
			   jiffies_to_msecs(part_stat_read(hd, time_in_queue))
			);
	}
	disk_part_iter_exit(&piter);

	return 0;
}
```

### iostat获取参数步骤
第一步，从/proc/cpuinfo中获取系统的cpu核心数，通过计算该文件中processor出现的次数便可以得到cpu的核心数；
第二步，如果/proc/diskstats文件存在，则为2.6版本；否则判断/proc/partitions是否存在，若存在，则为2.4版本；
第三步，读取文件/proc/diskstats获取磁盘名称，也就是获得F3的参数；
第四步：
1、获取/proc/diskstats中每个磁盘的数据
2、获取/proc/stat中的数据，计算cpu的平均时间
3、计算IO
```
blkio.rd_ios = new_blkio[p].rd_ios - old_blkio[p].rd_ios;
blkio.rd_merges = new_blkio[p].rd_merges - old_blkio[p].rd_merges;
blkio.rd_sectors = new_blkio[p].rd_sectors - old_blkio[p].rd_sectors;
blkio.rd_ticks = new_blkio[p].rd_ticks - old_blkio[p].rd_ticks;
blkio.wr_ios = new_blkio[p].wr_ios - old_blkio[p].wr_ios;
blkio.wr_merges = new_blkio[p].wr_merges - old_blkio[p].wr_merges; 
blkio.wr_sectors = new_blkio[p].wr_sectors - old_blkio[p].wr_sectors;
blkio.wr_ticks = new_blkio[p].wr_ticks - old_blkio[p].wr_ticks;
blkio.ticks = new_blkio[p].ticks - old_blkio[p].ticks;
blkio.aveq = new_blkio[p].aveq - old_blkio[p].aveq;
n_ios  = blkio.rd_ios + blkio.wr_ios;
n_ticks = blkio.rd_ticks + blkio.wr_ticks;
n_kbytes = (blkio.rd_sectors + blkio.wr_sectors) / 2.0;
queue = blkio.aveq / deltams;
size = n_ios ? n_kbytes / n_ios : 0.0;
wait = n_ios ? n_ticks / n_ios : 0.0;
svc_t = n_ios ? blkio.ticks / n_ios : 0.0;
busy = 100.0 * blkio.ticks / deltams; 
if (busy > 100.0) busy = 100.0;
```
4、计算CPU
5、存储当前数据

### iostat计算方式
“Δ”表示两次取样之间的差值，“Δt”表示采样周期。
tps：每秒I/O次数=[(Δrd_ios+Δwr_ios)/Δt]
r/s：每秒读操作的次数=[Δrd_ios/Δt]
w/s：每秒写操作的次数=[Δwr_ios/Δt]
rkB/s：每秒读取的千字节数=[Δrd_sectors/Δt]*[512/1024]
wkB/s：每秒写入的千字节数=[Δwr_sectors/Δt]*[512/1024]
rrqm/s：每秒合并读操作的次数=[Δrd_merges/Δt]
wrqm/s：每秒合并写操作的次数=[Δwr_merges/Δt]
avgrq-sz：每个I/O的平均扇区数=[Δrd_sectors+Δwr_sectors]/[Δrd_ios+Δwr_ios]
avgqu-sz：平均未完成的I/O请求数量=[Δtime_in_queue/Δt]
（平均未完成的I/O请求数量。）
await：每个I/O平均所需的时间=[Δrd_ticks+Δwr_ticks]/[Δrd_ios+Δwr_ios]
（不仅包括硬盘设备处理I/O的时间，还包括了在kernel队列中等待的时间。）
r_await：每个读操作平均所需的时间=[Δrd_ticks/Δrd_ios]
不仅包括硬盘设备读操作的时间，还包括了在kernel队列中等待的时间。
w_await：每个写操作平均所需的时间=[Δwr_ticks/Δwr_ios]
不仅包括硬盘设备写操作的时间，还包括了在kernel队列中等待的时间。
%util：该硬盘设备的繁忙比率=[Δio_ticks/Δt]

表示设备有I/O（即非空闲）的时间比率，不考虑I/O有多少，只考虑有没有。

***
**参考资料:**
优麒麟团队刘正元浅谈“Linux通用块层之IO合并”-https://www.ubuntukylin.com/news/791-cn.html
Linux IO请求处理流程-https://zhuanlan.zhihu.com/p/39199521/
iostat IO统计原理linux内核源码分析-https://blog.csdn.net/hu1610552336/article/details/110704158?spm=1001.2101.3001.6661.1&utm_medium=distribute.pc_relevant_t0.none-task-blog-2%7Edefault%7ECTRLIST%7Edefault-1-110704158-blog-118531859.pc_relevant_default&depth_1-utm_source=distribute.pc_relevant_t0.none-task-blog-2%7Edefault%7ECTRLIST%7Edefault-1-110704158-blog-118531859.pc_relevant_default&utm_relevant_index=1
iostat 磁盘性能统计-https://blog.csdn.net/chengm8/article/details/49251891