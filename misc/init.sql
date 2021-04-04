drop table if exists performance_info;
CREATE TABLE if not exists performance_info (
    id int(11) AUTO_INCREMENT primary key COMMENT '主键',
    name varchar(20) NOT NULL unique COMMENT '指标名',
    exec_path varchar(50) NOT NULL COMMENT '指标执行路径',
    instruction varchar(100) COMMENT '指标说明',
    state int NOT NULL COMMENT '状态'
) ENGINE=InnoDB DEFAULT CHARSET=utf8;
