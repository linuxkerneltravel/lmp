#ifndef __MYRQ_H__
#define __MYRQ_H__
/*
struct list_head {
	struct list_head *next;
	struct list_head *prev;
};
*/

struct rq;

typedef struct qspinlock arch_spinlock_t;

typedef struct raw_spinlock raw_spinlock_t;

struct uclamp_bucket {
	unsigned long value : bits_per(SCHED_CAPACITY_SCALE);
	unsigned long tasks : BITS_PER_LONG - bits_per(SCHED_CAPACITY_SCALE);
};

struct uclamp_rq {
	unsigned int value;
	struct uclamp_bucket bucket[UCLAMP_BUCKETS];
};

struct percpu_ref;

typedef void percpu_ref_func_t(struct percpu_ref *);

struct percpu_ref {
	atomic_long_t count;
	long unsigned int percpu_count_ptr;
	percpu_ref_func_t *release;
	percpu_ref_func_t *confirm_switch;
	bool force_atomic: 1;
	bool allow_reinit: 1;
	struct callback_head rcu;
};

struct cgroup_subsys_state {
	struct cgroup *cgroup;
	struct cgroup_subsys *ss;
	struct percpu_ref refcnt;
	struct list_head sibling;
	struct list_head children;
	struct list_head rstat_css_node;
	int id;
	unsigned int flags;
	u64 serial_nr;
	atomic_t online_cnt;
	struct work_struct destroy_work;
	struct rcu_work destroy_rwork;
	struct cgroup_subsys_state *parent;
};

struct cfs_bandwidth {
	raw_spinlock_t lock;
	ktime_t period;
	u64 quota;
	u64 runtime;
	s64 hierarchical_quota;
	u8 idle;
	u8 period_active;
	u8 distribute_running;
	u8 slack_started;
	struct hrtimer period_timer;
	struct hrtimer slack_timer;
	struct list_head throttled_cfs_rq;
	int nr_periods;
	int nr_throttled;
	u64 throttled_time;
};

struct task_group {
	struct cgroup_subsys_state css;
	struct sched_entity **se;
	struct cfs_rq **cfs_rq;
	long unsigned int shares;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	atomic_long_t load_avg;
	struct callback_head rcu;
	struct list_head list;
	struct task_group *parent;
	struct list_head siblings;
	struct list_head children;
	struct autogroup *autogroup;
	struct cfs_bandwidth cfs_bandwidth;
	unsigned int uclamp_pct[2];
	struct uclamp_se uclamp_req[2];
	struct uclamp_se uclamp[2];
};

struct cfs_rq {
	struct load_weight	load;
	unsigned long		runnable_weight;
	unsigned int		nr_running;
	unsigned int		h_nr_running;      /* SCHED_{NORMAL,BATCH,IDLE} */
	unsigned int		idle_h_nr_running; /* SCHED_IDLE */

	u64			exec_clock;
	u64			min_vruntime;
#ifndef CONFIG_64BIT
	u64			min_vruntime_copy;
#endif

	struct rb_root_cached	tasks_timeline;

	/*
	 * 'curr' points to currently running entity on this cfs_rq.
	 * It is set to NULL otherwise (i.e when none are currently running).
	 */
	struct sched_entity	*curr;
	struct sched_entity	*next;
	struct sched_entity	*last;
	struct sched_entity	*skip;

#ifdef	CONFIG_SCHED_DEBUG
	unsigned int		nr_spread_over;
#endif

#ifdef CONFIG_SMP
	/*
	 * CFS load tracking
	 */
	struct sched_avg	avg;
#ifndef CONFIG_64BIT
	u64			load_last_update_time_copy;
#endif
	struct {
		raw_spinlock_t	lock ____cacheline_aligned;
		int		nr;
		unsigned long	load_avg;
		unsigned long	util_avg;
		unsigned long	runnable_sum;
	} removed;

#ifdef CONFIG_FAIR_GROUP_SCHED
	unsigned long		tg_load_avg_contrib;
	long			propagate;
	long			prop_runnable_sum;

	/*
	 *   h_load = weight * f(tg)
	 *
	 * Where f(tg) is the recursive weight fraction assigned to
	 * this group.
	 */
	unsigned long		h_load;
	u64			last_h_load_update;
	struct sched_entity	*h_load_next;
#endif /* CONFIG_FAIR_GROUP_SCHED */
#endif /* CONFIG_SMP */

#ifdef CONFIG_FAIR_GROUP_SCHED
	struct rq		*rq;	/* CPU runqueue to which this cfs_rq is attached */

	/*
	 * leaf cfs_rqs are those that hold tasks (lowest schedulable entity in
	 * a hierarchy). Non-leaf lrqs hold other higher schedulable entities
	 * (like users, containers etc.)
	 *
	 * leaf_cfs_rq_list ties together list of leaf cfs_rq's in a CPU.
	 * This list is used during load balance.
	 */
	int			on_list;
	struct list_head	leaf_cfs_rq_list;
	struct task_group	*tg;	/* group that "owns" this runqueue */

#ifdef CONFIG_CFS_BANDWIDTH
	int			runtime_enabled;
	s64			runtime_remaining;

	u64			throttled_clock;
	u64			throttled_clock_task;
	u64			throttled_clock_task_time;
	int			throttled;
	int			throttle_count;
	struct list_head	throttled_list;
#endif /* CONFIG_CFS_BANDWIDTH */
#endif /* CONFIG_FAIR_GROUP_SCHED */
};

struct swait_queue_head {
	raw_spinlock_t lock;
	struct list_head task_list;
};

struct completion {
	unsigned int done;
	struct swait_queue_head wait;
};

typedef int (*cpu_stop_fn_t)(void *);

struct cpu_stop_done {
	atomic_t nr_todo;
	int ret;
	struct completion completion;
};

struct cpu_stop_work {
	struct list_head list;
	cpu_stop_fn_t fn;
	void *arg;
	struct cpu_stop_done *done;
};

struct rt_prio_array {
	DECLARE_BITMAP(bitmap, MAX_RT_PRIO+1); /* include 1 bit for delimiter */
	struct list_head queue[MAX_RT_PRIO];
};



struct rt_rq {
	struct rt_prio_array	active;
	unsigned int		rt_nr_running;
	unsigned int		rr_nr_running;
#if defined CONFIG_SMP || defined CONFIG_RT_GROUP_SCHED
	struct {
		int		curr; /* highest queued rt task prio */
#ifdef CONFIG_SMP
		int		next; /* next highest */
#endif
	} highest_prio;
#endif
#ifdef CONFIG_SMP
	unsigned long		rt_nr_migratory;
	unsigned long		rt_nr_total;
	int			overloaded;
	struct plist_head	pushable_tasks;

#endif /* CONFIG_SMP */
	int			rt_queued;

	int			rt_throttled;
	u64			rt_time;
	u64			rt_runtime;
	/* Nests inside the rq lock: */
	raw_spinlock_t		rt_runtime_lock;

#ifdef CONFIG_RT_GROUP_SCHED
	unsigned long		rt_nr_boosted;

	struct rq		*rq;
	struct task_group	*tg;
#endif
};

struct dl_bw {
	raw_spinlock_t lock;
	u64 bw;
	u64 total_bw;
};

struct dl_rq {
	/* runqueue is an rbtree, ordered by deadline */
	struct rb_root_cached	root;

	unsigned long		dl_nr_running;

#ifdef CONFIG_SMP
	/*
	 * Deadline values of the currently executing and the
	 * earliest ready task on this rq. Caching these facilitates
	 * the decision whether or not a ready but not running task
	 * should migrate somewhere else.
	 */
	struct {
		u64		curr;
		u64		next;
	} earliest_dl;

	unsigned long		dl_nr_migratory;
	int			overloaded;

	/*
	 * Tasks on this rq that can be pushed away. They are kept in
	 * an rb-tree, ordered by tasks' deadlines, with caching
	 * of the leftmost (earliest deadline) element.
	 */
	struct rb_root_cached	pushable_dl_tasks_root;
#else
	struct dl_bw		dl_bw;
#endif
	/*
	 * "Active utilization" for this runqueue: increased when a
	 * task wakes up (becomes TASK_RUNNING) and decreased when a
	 * task blocks
	 */
	u64			running_bw;

	/*
	 * Utilization of the tasks "assigned" to this runqueue (including
	 * the tasks that are in runqueue and the tasks that executed on this
	 * CPU and blocked). Increased when a task moves to this runqueue, and
	 * decreased when the task moves away (migrates, changes scheduling
	 * policy, or terminates).
	 * This is needed to compute the "inactive utilization" for the
	 * runqueue (inactive utilization = this_bw - running_bw).
	 */
	u64			this_bw;
	u64			extra_bw;

	/*
	 * Inverse of the fraction of CPU utilization that can be reclaimed
	 * by the GRUB algorithm.
	 */
	u64			bw_ratio;
};

typedef struct cpumask *cpumask_var_t;

struct cpudl_item {
	u64 dl;
	int cpu;
	int idx;
};

struct cpudl {
	raw_spinlock_t lock;
	int size;
	cpumask_var_t free_cpus;
	struct cpudl_item *elements;
};

struct irq_work {
	long unsigned int flags;
	struct llist_node llnode;
	void (*func)(struct irq_work *);
};

struct cpupri_vec {
	atomic_t count;
	cpumask_var_t mask;
};

struct cpupri {
	struct cpupri_vec pri_to_cpu[102];
	int *cpu_to_pri;
};

struct em_perf_domain {};

struct perf_domain {
	struct em_perf_domain *em_pd;
	struct perf_domain *next;
	struct callback_head rcu;
};

struct root_domain {
	atomic_t refcount;
	atomic_t rto_count;
	struct callback_head rcu;
	cpumask_var_t span;
	cpumask_var_t online;
	int overload;
	int overutilized;
	cpumask_var_t dlo_mask;
	atomic_t dlo_count;
	struct dl_bw dl_bw;
	struct cpudl cpudl;
	struct irq_work rto_push_work;
	raw_spinlock_t rto_lock;
	int rto_loop;
	int rto_cpu;
	atomic_t rto_loop_next;
	atomic_t rto_loop_start;
	cpumask_var_t rto_mask;
	struct cpupri cpupri;
	long unsigned int max_cpu_capacity;
	struct perf_domain *pd;
};

struct sched_domain_shared {
	atomic_t ref;
	atomic_t nr_busy_cpus;
	int has_idle_cores;
};

struct sched_group {
	struct sched_group *next;
	atomic_t ref;
	unsigned int group_weight;
	struct sched_group_capacity *sgc;
	int asym_prefer_cpu;
	long unsigned int cpumask[0];
};

struct sched_group_capacity {
	atomic_t ref;
	long unsigned int capacity;
	long unsigned int min_capacity;
	long unsigned int max_capacity;
	long unsigned int next_update;
	int imbalance;
	int id;
	long unsigned int cpumask[0];
};

struct sched_domain {
	struct sched_domain *parent;
	struct sched_domain *child;
	struct sched_group *groups;
	long unsigned int min_interval;
	long unsigned int max_interval;
	unsigned int busy_factor;
	unsigned int imbalance_pct;
	unsigned int cache_nice_tries;
	int nohz_idle;
	int flags;
	int level;
	long unsigned int last_balance;
	unsigned int balance_interval;
	unsigned int nr_balance_failed;
	u64 max_newidle_lb_cost;
	long unsigned int next_decay_max_lb_cost;
	u64 avg_scan_cost;
	unsigned int lb_count[3];
	unsigned int lb_failed[3];
	unsigned int lb_balanced[3];
	unsigned int lb_imbalance[3];
	unsigned int lb_gained[3];
	unsigned int lb_hot_gained[3];
	unsigned int lb_nobusyg[3];
	unsigned int lb_nobusyq[3];
	unsigned int alb_count;
	unsigned int alb_failed;
	unsigned int alb_pushed;
	unsigned int sbe_count;
	unsigned int sbe_balanced;
	unsigned int sbe_pushed;
	unsigned int sbf_count;
	unsigned int sbf_balanced;
	unsigned int sbf_pushed;
	unsigned int ttwu_wake_remote;
	unsigned int ttwu_move_affine;
	unsigned int ttwu_move_balance;
	char *name;
	union {
		void *private;
		struct callback_head rcu;
	};
	struct sched_domain_shared *shared;
	unsigned int span_weight;
	long unsigned int span[0];
};

typedef struct __call_single_data call_single_data_t;

struct cpuidle_state_usage {
	long long unsigned int disable;
	long long unsigned int usage;
	long long unsigned int time;
	long long unsigned int above;
	long long unsigned int below;
	long long unsigned int s2idle_usage;
	long long unsigned int s2idle_time;
};

struct kref {
	refcount_t refcount;
};

struct kobject;

struct kobj_type {
	void (*release)(struct kobject *);
	const struct sysfs_ops *sysfs_ops;
	struct attribute **default_attrs;
	const struct attribute_group **default_groups;
	const struct kobj_ns_type_operations * (*child_ns_type)(struct kobject *);
	const void * (*namespace)(struct kobject *);
	void (*get_ownership)(struct kobject *, kuid_t *, kgid_t *);
};

struct kobject {
	const char *name;
	struct list_head entry;
	struct kobject *parent;
	struct kset *kset;
	struct kobj_type *ktype;
	struct kernfs_node *sd;
	struct kref kref;
	unsigned int state_initialized: 1;
	unsigned int state_in_sysfs: 1;
	unsigned int state_add_uevent_sent: 1;
	unsigned int state_remove_uevent_sent: 1;
	unsigned int uevent_suppress: 1;
};

struct cpuidle_state_kobj {
	struct cpuidle_state *state;
	struct cpuidle_state_usage *state_usage;
	struct completion kobj_unregister;
	struct kobject kobj;
	struct cpuidle_device *device;
};

struct cpuidle_device {
	unsigned int registered: 1;
	unsigned int enabled: 1;
	unsigned int use_deepest_state: 1;
	unsigned int poll_time_limit: 1;
	unsigned int cpu;
	ktime_t next_hrtimer;
	int last_state_idx;
	int last_residency;
	u64 poll_limit_ns;
	struct cpuidle_state_usage states_usage[10];
	struct cpuidle_state_kobj *kobjs[10];
	struct cpuidle_driver_kobj *kobj_driver;
	struct cpuidle_device_kobj *kobj_dev;
	struct list_head device_list;
};

struct cpuidle_device_kobj {
	struct cpuidle_device *dev;
	struct completion kobj_unregister;
	struct kobject kobj;
};

struct cpuidle_driver;

struct cpuidle_state {
	char name[16];
	char desc[32];
	unsigned int flags;
	unsigned int exit_latency;
	int power_usage;
	unsigned int target_residency;
	bool disabled;
	int (*enter)(struct cpuidle_device *, struct cpuidle_driver *, int);
	int (*enter_dead)(struct cpuidle_device *, int);
	void (*enter_s2idle)(struct cpuidle_device *, struct cpuidle_driver *, int);
};

struct cpuidle_driver {
	const char *name;
	struct module *owner;
	int refcnt;
	unsigned int bctimer: 1;
	struct cpuidle_state states[10];
	int state_count;
	int safe_state_index;
	struct cpumask *cpumask;
	const char *governor;
};

// struct rq {
// 	/* runqueue lock: */
// 	raw_spinlock_t		lock;

// 	/*
// 	 * nr_running and cpu_load should be in the same cacheline because
// 	 * remote CPUs use both these fields when doing load calculation.
// 	 */
// 	unsigned int		nr_running;
// #ifdef CONFIG_NUMA_BALANCING
// 	unsigned int		nr_numa_running;
// 	unsigned int		nr_preferred_running;
// 	unsigned int		numa_migrate_on;
// #endif
// #ifdef CONFIG_NO_HZ_COMMON
// #ifdef CONFIG_SMP
// 	unsigned long		last_load_update_tick;
// 	unsigned long		last_blocked_load_update_tick;
// 	unsigned int		has_blocked_load;
// #endif /* CONFIG_SMP */
// 	unsigned int		nohz_tick_stopped;
// 	atomic_t nohz_flags;
// #endif /* CONFIG_NO_HZ_COMMON */

// 	unsigned long		nr_load_updates;
// 	u64			nr_switches;

// #ifdef CONFIG_UCLAMP_TASK
// 	/* Utilization clamp values based on CPU's RUNNABLE tasks */
// 	struct uclamp_rq	uclamp[UCLAMP_CNT] ____cacheline_aligned;
// 	unsigned int		uclamp_flags;
// #define UCLAMP_FLAG_IDLE 0x01
// #endif

// 	struct cfs_rq		cfs;
// 	struct rt_rq		rt;
// 	struct dl_rq		dl;

// #ifdef CONFIG_FAIR_GROUP_SCHED
// 	/* list of leaf cfs_rq on this CPU: */
// 	struct list_head	leaf_cfs_rq_list;
// 	struct list_head	*tmp_alone_branch;
// #endif /* CONFIG_FAIR_GROUP_SCHED */

// 	/*
// 	 * This is part of a global counter where only the total sum
// 	 * over all CPUs matters. A task can increase this counter on
// 	 * one CPU and if it got migrated afterwards it may decrease
// 	 * it on another CPU. Always updated under the runqueue lock:
// 	 */
// 	unsigned long		nr_uninterruptible;

// 	struct task_struct	*curr;
// 	struct task_struct	*idle;
// 	struct task_struct	*stop;
// 	unsigned long		next_balance;
// 	struct mm_struct	*prev_mm;

// 	unsigned int		clock_update_flags;
// 	u64			clock;
// 	/* Ensure that all clocks are in the same cache line */
// 	u64			clock_task ____cacheline_aligned;
// 	u64			clock_pelt;
// 	unsigned long		lost_idle_time;

// 	atomic_t		nr_iowait;

// #ifdef CONFIG_MEMBARRIER
// 	int membarrier_state;
// #endif

// #ifdef CONFIG_SMP
// 	struct root_domain		*rd;
// 	struct sched_domain __rcu	*sd;

// 	unsigned long		cpu_capacity;
// 	unsigned long		cpu_capacity_orig;

// 	struct callback_head	*balance_callback;

// 	unsigned char		idle_balance;

// 	unsigned long		misfit_task_load;

// 	/* For active balancing */
// 	int			active_balance;
// 	int			push_cpu;
// 	struct cpu_stop_work	active_balance_work;

// 	/* CPU of this runqueue: */
// 	int			cpu;
// 	int			online;

// 	struct list_head cfs_tasks;

// 	struct sched_avg	avg_rt;
// 	struct sched_avg	avg_dl;
// #ifdef CONFIG_HAVE_SCHED_AVG_IRQ
// 	struct sched_avg	avg_irq;
// #endif
// 	u64			idle_stamp;
// 	u64			avg_idle;

// 	/* This is used to determine avg_idle's max value */
// 	u64			max_idle_balance_cost;
// #endif

// #ifdef CONFIG_IRQ_TIME_ACCOUNTING
// 	u64			prev_irq_time;
// #endif
// #ifdef CONFIG_PARAVIRT
// 	u64			prev_steal_time;
// #endif
// #ifdef CONFIG_PARAVIRT_TIME_ACCOUNTING
// 	u64			prev_steal_time_rq;
// #endif

// 	/* calc_load related fields */
// 	unsigned long		calc_load_update;
// 	long			calc_load_active;

// #ifdef CONFIG_SCHED_HRTICK
// #ifdef CONFIG_SMP
// 	int			hrtick_csd_pending;
// 	call_single_data_t	hrtick_csd;
// #endif
// 	struct hrtimer		hrtick_timer;
// #endif

// #ifdef CONFIG_SCHEDSTATS
// 	/* latency stats */
// 	struct sched_info	rq_sched_info;
// 	unsigned long long	rq_cpu_time;
// 	/* could above be rq->cfs_rq.exec_clock + rq->rt_rq.rt_runtime ? */

// 	/* sys_sched_yield() stats */
// 	unsigned int		yld_count;

// 	/* schedule() stats */
// 	unsigned int		sched_count;
// 	unsigned int		sched_goidle;

// 	/* try_to_wake_up() stats */
// 	unsigned int		ttwu_count;
// 	unsigned int		ttwu_local;
// #endif

// #ifdef CONFIG_SMP
// 	struct llist_head	wake_list;
// #endif

// #ifdef CONFIG_CPU_IDLE
// 	/* Must be inspected within a rcu lock section */
// 	struct cpuidle_state	*idle_state;
// #endif
// };


struct rq {
	raw_spinlock_t lock;
	unsigned int nr_running;
	unsigned int nr_numa_running;
	unsigned int nr_preferred_running;
	unsigned int numa_migrate_on;
	long unsigned int last_load_update_tick;
	long unsigned int last_blocked_load_update_tick;
	unsigned int has_blocked_load;
	unsigned int nohz_tick_stopped;
	atomic_t nohz_flags;
	long unsigned int nr_load_updates;
	u64 nr_switches;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	struct uclamp_rq uclamp[2];
	unsigned int uclamp_flags;
	long: 32;
	long: 64;
	long: 64;
	long: 64;
	struct cfs_rq cfs;
	struct rt_rq rt;
	struct dl_rq dl;
	struct list_head leaf_cfs_rq_list;
	struct list_head *tmp_alone_branch;
	long unsigned int nr_uninterruptible;
	struct task_struct *curr;
	struct task_struct *idle;
	struct task_struct *stop;
	long unsigned int next_balance;
	struct mm_struct *prev_mm;
	unsigned int clock_update_flags;
	u64 clock;
	long: 64;
	long: 64;
	long: 64;
	u64 clock_task;
	u64 clock_pelt;
	long unsigned int lost_idle_time;
	atomic_t nr_iowait;
	int membarrier_state;
	struct root_domain *rd;
	struct sched_domain *sd;
	long unsigned int cpu_capacity;
	long unsigned int cpu_capacity_orig;
	struct callback_head *balance_callback;
	unsigned char idle_balance;
	long unsigned int misfit_task_load;
	int active_balance;
	int push_cpu;
	struct cpu_stop_work active_balance_work;
	int cpu;
	int online;
	struct list_head cfs_tasks;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	struct sched_avg avg_rt;
	struct sched_avg avg_dl;
	u64 idle_stamp;
	u64 avg_idle;
	u64 max_idle_balance_cost;
	u64 prev_steal_time;
	long unsigned int calc_load_update;
	long int calc_load_active;
	int hrtick_csd_pending;
	long: 32;
	long: 64;
	call_single_data_t hrtick_csd;
	struct hrtimer hrtick_timer;
	ktime_t hrtick_time;
	struct sched_info rq_sched_info;
	long long unsigned int rq_cpu_time;
	unsigned int yld_count;
	unsigned int sched_count;
	unsigned int sched_goidle;
	unsigned int ttwu_count;
	unsigned int ttwu_local;
	struct llist_head wake_list;
	struct cpuidle_state *idle_state;
	long: 64;
};

#endif
