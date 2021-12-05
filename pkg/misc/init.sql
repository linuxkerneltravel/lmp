CREATE DATABASE IF NOT EXISTS lmp;
use lmp;
drop table if exists performance_index;
CREATE TABLE if NOT EXISTS performance_index (
    id int(11) AUTO_INCREMENT PRIMARY KEY COMMENT '主键',
    plugin_name varchar(30) NOT NULL unique COMMENT '指标名',
    plugin_type varchar(10) NOT NULL COMMENT '指标类型',
    exec_path varchar(50) NOT NULL COMMENT '指标执行路径',
    instruction varchar(100) COMMENT '指标说明',
    state int NOT NULL COMMENT '状态'
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

INSERT INTO performance_index(plugin_name, plugin_type, exec_path, instruction, state) VALUES("containerNet", "bcc", "./plugins/net/ContainerNet.py", "empty", 0);
INSERT INTO performance_index(plugin_name, plugin_type, exec_path, instruction, state) VALUES("cpuUtilize", "bcc", "./plugins/cpu/cpuutilize.py", "empty", 0);
INSERT INTO performance_index(plugin_name, plugin_type, exec_path, instruction, state) VALUES("hardDiskReadWriteTime", "bcc", "./plugins/fs/harddiskreadwritetime.py", "empty", 0);
INSERT INTO performance_index(plugin_name, plugin_type, exec_path, instruction, state) VALUES("irq", "bcc", "./plugins/mm/irq.py", "empty", 0);
INSERT INTO performance_index(plugin_name, plugin_type, exec_path, instruction, state) VALUES("memUsage", "bcc", "./plugins/mm/memusage.py", "empty", 0);
INSERT INTO performance_index(plugin_name, plugin_type, exec_path, instruction, state) VALUES("netLatency", "bcc", "./plugins/net/netlatency.py", "empty", 0);
INSERT INTO performance_index(plugin_name, plugin_type, exec_path, instruction, state) VALUES("pickNext", "bcc", "./plugins/cpu/picknext.py", "empty", 0);
INSERT INTO performance_index(plugin_name, plugin_type, exec_path, instruction, state) VALUES("taskSwitch", "bcc", "./plugins/cpu/taskswitch.py", "empty", 0);
INSERT INTO performance_index(plugin_name, plugin_type, exec_path, instruction, state) VALUES("vfsStat", "bcc", "./plugins/fs/vfsstat.py", "empty", 0);
INSERT INTO performance_index(plugin_name, plugin_type, exec_path, instruction, state) VALUES("waitingQueueLength", "bcc", "./plugins/cpu/waitingqueuelength.py", "empty", 0);
INSERT INTO performance_index(plugin_name, plugin_type, exec_path, instruction, state) VALUES("oomkill", "bcc", "./plugins/mm/oomkill.py", "empty", 0);
INSERT INTO performance_index(plugin_name, plugin_type, exec_path, instruction, state) VALUES("runqslower", "bcc", "./plugins/cpu/runqslower.py", "empty", 0);
INSERT INTO performance_index(plugin_name, plugin_type, exec_path, instruction, state) VALUES("slabratetop", "bcc", "./plugins/mm/slabratetop.py", "empty", 0);
INSERT INTO performance_index(plugin_name, plugin_type, exec_path, instruction, state) VALUES("memleak", "bcc", "./plugins/mm/memleak.py", "empty", 0);
INSERT INTO performance_index(plugin_name, plugin_type, exec_path, instruction, state) VALUES("shmsnoop", "bcc", "./plugins/mm/shmsnoop.py", "empty", 0);
INSERT INTO performance_index(plugin_name, plugin_type, exec_path, instruction, state) VALUES("drsnoop", "bcc", "./plugins/mm/drsnoop.py", "empty", 0);
INSERT INTO performance_index(plugin_name, plugin_type, exec_path, instruction, state) VALUES("cachetop", "bcc", "./plugins/fs/cachetop.py", "empty", 0);
INSERT INTO performance_index(plugin_name, plugin_type, exec_path, instruction, state) VALUES("filetop", "bcc", "./plugins/fs/filetop.py", "empty", 0);
INSERT INTO performance_index(plugin_name, plugin_type, exec_path, instruction, state) VALUES("runqlat", "bcc", "./plugins/cpu/runqlat.py", "empty", 0);
INSERT INTO performance_index(plugin_name, plugin_type, exec_path, instruction, state) VALUES("softirqs", "bcc", "./plugins/cpu/softirqs.py", "empty", 0);
INSERT INTO performance_index(plugin_name, plugin_type, exec_path, instruction, state) VALUES("cpudist", "bcc", "./plugins/cpu/cpudist.py", "empty", 0);
INSERT INTO performance_index(plugin_name, plugin_type, exec_path, instruction, state) VALUES("sofdsnoop", "bcc", "./plugins/net/sofdsnoop.py", "empty", 0);
INSERT INTO performance_index(plugin_name, plugin_type, exec_path, instruction, state) VALUES("filelife", "bcc", "./plugins/fs/filelife.py", "empty", 0);
INSERT INTO performance_index(plugin_name, plugin_type, exec_path, instruction, state) VALUES("cachestat", "bcc", "./plugins/fs/cachestat.py", "empty", 0);
INSERT INTO performance_index(plugin_name, plugin_type, exec_path, instruction, state) VALUES("dcstat", "bcc", "./plugins/fs/dcstat.py", "empty", 0);
INSERT INTO performance_index(plugin_name, plugin_type, exec_path, instruction, state) VALUES("dcsnoop", "bcc", "./plugins/fs/dcsnoop.py", "empty", 0);
INSERT INTO performance_index(plugin_name, plugin_type, exec_path, instruction, state) VALUES("fileslower", "bcc", "./plugins/fs/fileslower.py", "empty", 0);
INSERT INTO performance_index(plugin_name, plugin_type, exec_path, instruction, state) VALUES("vfscount", "bcc", "./plugins/fs/vfscount.py", "empty", 0);
INSERT INTO performance_index(plugin_name, plugin_type, exec_path, instruction, state) VALUES("mountsnoop", "bcc", "./plugins/fs/mountsnoop.py", "empty", 0);
INSERT INTO performance_index(plugin_name, plugin_type, exec_path, instruction, state) VALUES("mdflush", "bcc", "./plugins/fs/mdflush.py", "empty", 0);
INSERT INTO performance_index(plugin_name, plugin_type, exec_path, instruction, state) VALUES("biotop", "bcc", "./plugins/fs/biotop.py", "empty", 0);
INSERT INTO performance_index(plugin_name, plugin_type, exec_path, instruction, state) VALUES("biosnoop", "bcc", "./plugins/fs/biosnoop.py", "empty", 0);
INSERT INTO performance_index(plugin_name, plugin_type, exec_path, instruction, state) VALUES("ext4slower", "bcc", "./plugins/fs/ext4slower.py", "empty", 0);
INSERT INTO performance_index(plugin_name, plugin_type, exec_path, instruction, state) VALUES("tcptop", "bcc", "./plugins/net/tcptop.py", "empty", 0);
INSERT INTO performance_index(plugin_name, plugin_type, exec_path, instruction, state) VALUES("tcplife", "bcc", "./plugins/net/tcplife.py", "empty", 0);
INSERT INTO performance_index(plugin_name, plugin_type, exec_path, instruction, state) VALUES("tcptracer", "bcc", "./plugins/net/tcptracer.py", "empty", 0);
INSERT INTO performance_index(plugin_name, plugin_type, exec_path, instruction, state) VALUES("tcpconnect", "bcc", "./plugins/net/tcpconnect.py", "empty", 0);
INSERT INTO performance_index(plugin_name, plugin_type, exec_path, instruction, state) VALUES("tcpconnlat", "bcc", "./plugins/net/tcpconnlat.py", "empty", 0);
INSERT INTO performance_index(plugin_name, plugin_type, exec_path, instruction, state) VALUES("tcpretrans", "bcc", "./plugins/net/tcpretrans.py", "empty", 0);
INSERT INTO performance_index(plugin_name, plugin_type, exec_path, instruction, state) VALUES("tcpsubnet", "bcc", "./plugins/net/tcpsubnet.py", "empty", 0);
INSERT INTO performance_index(plugin_name, plugin_type, exec_path, instruction, state) VALUES("tcpdrop", "bcc", "./plugins/net/tcpdrop.py", "empty", 0);
INSERT INTO performance_index(plugin_name, plugin_type, exec_path, instruction, state) VALUES("btrfsdist", "bcc", "./plugins/fs/btrfsdist.py", "empty", 0);
INSERT INTO performance_index(plugin_name, plugin_type, exec_path, instruction, state) VALUES("btrfsslower", "bcc", "./plugins/fs/btrfsslower.py", "empty", 0);
INSERT INTO performance_index(plugin_name, plugin_type, exec_path, instruction, state) VALUES("xfsslower", "bcc", "./plugins/fs/xfsslower.py", "empty", 0);
INSERT INTO performance_index(plugin_name, plugin_type, exec_path, instruction, state) VALUES("nfsslower", "bcc", "./plugins/fs/nfsslower.py", "empty", 0);
INSERT INTO performance_index(plugin_name, plugin_type, exec_path, instruction, state) VALUES("zfsslower", "bcc", "./plugins/fs/zfsslower.py", "empty", 0);
INSERT INTO performance_index(plugin_name, plugin_type, exec_path, instruction, state) VALUES("zfsdist", "bcc", "./plugins/fs/zfsdist.py", "empty", 0);
INSERT INTO performance_index(plugin_name, plugin_type, exec_path, instruction, state) VALUES("nfsdist", "bcc", "./plugins/fs/nfsdist.py", "empty", 0);
INSERT INTO performance_index(plugin_name, plugin_type, exec_path, instruction, state) VALUES("xfsdist", "bcc", "./plugins/fs/xfsdist.py", "empty", 0);
INSERT INTO performance_index(plugin_name, plugin_type, exec_path, instruction, state) VALUES("ext4dist", "bcc", "./plugins/fs/ext4dist.py", "empty", 0);
