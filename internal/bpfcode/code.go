//
// Created by ChenYuZhao
//
package bpfcode

//for vfsstat
const (
	Vfsstatdatatype = `
enum stat_types {
	S_READ = 1,
	S_WRITE,
	S_FSYNC,
	S_OPEN,
	S_CREATE,
	S_MAXSTAT
};

BPF_ARRAY(stats, u64, S_MAXSTAT);
	`
	Vfsstatcode = `
static void stats_increment(int key) {
	u64 *leaf = stats.lookup(&key);
	if (leaf) (*leaf)++;
}

void do_read(struct pt_regs *ctx) { stats_increment(S_READ); }
void do_write(struct pt_regs *ctx) { stats_increment(S_WRITE); }
void do_fsync(struct pt_regs *ctx) { stats_increment(S_FSYNC); }
void do_open(struct pt_regs *ctx) { stats_increment(S_OPEN); }
void do_create(struct pt_regs *ctx) { stats_increment(S_CREATE); }
	`

	TIMESTAMP = `
interval = 1
`
	ATTACHKPROBE = `
b.attach_kprobe(event="vfs_read", fn_name="do_read")
b.attach_kprobe(event="vfs_write", fn_name="do_write")
b.attach_kprobe(event="vfs_fsync", fn_name="do_fsync")
b.attach_kprobe(event="vfs_open", fn_name="do_open")
b.attach_kprobe(event="vfs_create", fn_name="do_create")
`
	VFSSTATTYPES = `
stat_types = {
    "READ": 1,
    "WRITE": 2,
    "FSYNC": 3,
    "OPEN": 4,
    "CREATE": 5
}
`
	VFSSTATCODE = `
    for stype in stat_types.keys():
        idx = stat_types[stype]
        try:
            val = b["stats"][c_int(idx)].value / interval
            print("%d " % val, end="")
        except:
            print("%d" % 0, end="")
    b["stats"].clear()
    print("")
`
)
