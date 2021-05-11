drop table if exists performance_index;
CREATE TABLE if NOT EXISTS performance_index (
    id int(11) AUTO_INCREMENT PRIMARY KEY COMMENT '主键',
    name varchar(20) NOT NULL unique COMMENT '指标名',
    exec_path varchar(50) NOT NULL COMMENT '指标执行路径',
    instruction varchar(100) COMMENT '指标说明',
    state int NOT NULL COMMENT '状态'
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

INSERT INTO performance_index(name, exec_path, instruction, state) VALUES("containerNet", "./plugins/ContainerNet.py", "empty", 0);
INSERT INTO performance_index(name, exec_path, instruction, state) VALUES("cpuUtilize", "./plugins/cpuutilize.py", "empty", 0);
INSERT INTO performance_index(name, exec_path, instruction, state) VALUES("hardDiskReadWriteTime", "./plugins/harddiskreadwritetime.py", "empty", 0);
INSERT INTO performance_index(name, exec_path, instruction, state) VALUES("irq", "./plugins/irq.py", "empty", 0);
INSERT INTO performance_index(name, exec_path, instruction, state) VALUES("memUsage", "./plugins/memusage.py", "empty", 0);
INSERT INTO performance_index(name, exec_path, instruction, state) VALUES("netLatency", "./plugins/netlatency.py", "empty", 0);
INSERT INTO performance_index(name, exec_path, instruction, state) VALUES("pickNext", "./plugins/picknext.py", "empty", 0);
INSERT INTO performance_index(name, exec_path, instruction, state) VALUES("taskSwitch", "./plugins/taskswitch.py", "empty", 0);
INSERT INTO performance_index(name, exec_path, instruction, state) VALUES("vfsStat", "./plugins/vfsstat.py", "empty", 0);
INSERT INTO performance_index(name, exec_path, instruction, state) VALUES("waitingQueueLength", "./plugins/waitingqueuelength.py", "empty", 0);

