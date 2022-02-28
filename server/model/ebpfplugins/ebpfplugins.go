package ebpfplugins

import (
	"lmp/server/global"
)

/*
CREATE TABLE if NOT EXISTS performance_index (
    id int(11) AUTO_INCREMENT PRIMARY KEY COMMENT '主键',
    plugin_name varchar(30) NOT NULL unique COMMENT '指标名',
    plugin_type varchar(10) NOT NULL COMMENT '指标类型',
    exec_path varchar(50) NOT NULL COMMENT '指标执行路径',
    instruction varchar(100) COMMENT '指标说明',
    state int NOT NULL COMMENT '状态'
) ENGINE=InnoDB DEFAULT CHARSET=utf8;
*/

type EbpfPlugins struct {
	global.GVA_MODEL
	PluginName string `json:"pluginName"  gorm:"comment:插件名"`
	PluginType uint   `json:"pluginType"  gorm:"comment:插件类型: 0: demo，1: bcc, 2: c 3:golang"` // 0: demo，1: bcc, 2: c 3:golang
	PluginPath string `json:"pluginPath" gorm:"comment:插件执行路径"`
	Intro      string `json:"intro" gorm:"comment:插件说明"`
	Content    string `json:"content" gorm:"comment:插件内容"`
	DocUrl     string `json:"docUrl" gorm:"comment:插件文档说明地址"`
	GfConf     string `json:"gfConf" gorm:"comment:插件grafana报表内容"`
	GfUrl      string `json:"gfUrl" gorm:"comment:插件grafana报表地址"`
	State      uint   `json:"state" gorm:"comment:插件状态:0 未加载到内核中运行，1 成功加载内核中运行"` // 0 未加载到内核中运行，1 成功加载内核中运行
	Enable     uint   `json:"enable" gorm:"comment:插件状态:0 未启用，1启用"`              // 0 未启用，1启用
}
