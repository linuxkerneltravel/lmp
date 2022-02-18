package ebpfplugins

import (
	"fmt"

	"lmp/server/global"
	"lmp/server/model/ebpfplugins"

	"github.com/pkg/errors"
	"gorm.io/gorm"
)

var Ebpfplugins = new(eplugins)

type eplugins struct{}

func (e *eplugins) TableName() string {
	return "ebpf_plugins"
}

func (e *eplugins) Initialize() error {
	entities := []ebpfplugins.EbpfPlugins{
		{PluginName: "containerNet", PluginType: 0, PluginPath: "../plugins/net/ContainerNet.py", DocUrl: "http://lmp.kerneltravel.net/", Intro: "empty", State: 0, Enable: 1},
		{PluginName: "cpudist", PluginType: 0, PluginPath: "../plugins/cpu/cpudist.py", DocUrl: "http://lmp.kerneltravel.net/", Intro: "empty", State: 0, Enable: 1},
		{PluginName: "cpuidle", PluginType: 0, PluginPath: "../plugins/cpu/cpudile.py", DocUrl: "http://lmp.kerneltravel.net/", Intro: "empty", State: 0, Enable: 1},
		{PluginName: "irq", PluginType: 0, PluginPath: "../plugins/cpu/irq.py", DocUrl: "http://lmp.kerneltravel.net/monitor/cpu/irq/", Intro: "empty", State: 0, Enable: 1},
		{PluginName: "vfscount", PluginType: 0, PluginPath: "../plugins/fs/vfscount.py", DocUrl: "http://lmp.kerneltravel.net/monitor/fs/vfscont/", Intro: "empty", State: 0, Enable: 1},
		{PluginName: "test", PluginType: 0, PluginPath: "../plugins/test.py", DocUrl: "", Intro: "empty", State: 0, Enable: 1},
	}
	if err := global.GVA_DB.Create(&entities).Error; err != nil { // 创建 model.ExaEbpfplugins 初始化数据
		return errors.Wrap(err, e.TableName()+"表数据初始化失败!")
	}
	return nil
}

func (e *eplugins) CheckDataExist() bool {
	if errors.Is(global.GVA_DB.Where("plugin_name = ?", "containerNet").First(&ebpfplugins.EbpfPlugins{}).Error,
		gorm.ErrRecordNotFound) { // 判断是否存在数据
		fmt.Println("no data")
		return false
	}
	fmt.Println("exa_ebpfplugins has data")
	return true
}
