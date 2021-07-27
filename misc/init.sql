CREATE DATABASE IF NOT EXISTS lmp;
use lmp;
drop table performance_index if exists performance_index;
CREATE TABLE if NOT EXISTS performance_index (
    id int(11) AUTO_INCREMENT PRIMARY KEY COMMENT '主键',
    plugin_name varchar(30) NOT NULL unique COMMENT '指标名',
    plugin_type varchar(10) NOT NULL COMMENT '指标类型',
    exec_path varchar(50) NOT NULL COMMENT '指标执行路径',
    instruction varchar(100) COMMENT '指标说明',
    state int NOT NULL COMMENT '状态'
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

INSERT INTO performance_index(plugin_name, plugin_type, exec_path, instruction, state) VALUES("ContainerNet", "bcc", "./plugins/ContainerNet.py", "empty", 0);
INSERT INTO performance_index(plugin_name, plugin_type, exec_path, instruction, state) VALUES("CpuUtilize", "bcc", "./plugins/CpuUtilize.py", "empty", 0);
INSERT INTO performance_index(plugin_name, plugin_type, exec_path, instruction, state) VALUES("DiskReadWriteTime", "bcc", "./plugins/DiskReadWriteTime.py", "empty", 0);
INSERT INTO performance_index(plugin_name, plugin_type, exec_path, instruction, state) VALUES("Irq", "bcc", "./plugins/Irq.py", "empty", 0);
INSERT INTO performance_index(plugin_name, plugin_type, exec_path, instruction, state) VALUES("MemUsage", "bcc", "./plugins/MemUsage.py", "empty", 0);
INSERT INTO performance_index(plugin_name, plugin_type, exec_path, instruction, state) VALUES("NetworkLatency", "bcc", "./plugins/NetworkLatency.py", "empty", 0);
INSERT INTO performance_index(plugin_name, plugin_type, exec_path, instruction, state) VALUES("PickNext", "bcc", "./plugins/PickNext.py", "empty", 0);
INSERT INTO performance_index(plugin_name, plugin_type, exec_path, instruction, state) VALUES("TaskSwitch", "bcc", "./plugins/TaskSwitch.py", "empty", 0);
INSERT INTO performance_index(plugin_name, plugin_type, exec_path, instruction, state) VALUES("VfsStat", "bcc", "./plugins/VfsStat.py", "empty", 0);
INSERT INTO performance_index(plugin_name, plugin_type, exec_path, instruction, state) VALUES("WaitingQueueLength", "bcc", "./plugins/WaitingQueueLength.py", "empty", 0);

