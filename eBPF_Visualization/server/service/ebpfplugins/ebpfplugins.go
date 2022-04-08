package ebpfplugins

import (
	"errors"
	"io/ioutil"
	"lmp/server/global"
	"lmp/server/model/common/request"
	"lmp/server/model/ebpfplugins"
)

type EbpfpluginsService struct{}

//@author: [helight](https://github.com/hellight)
//@function: CreateEbpfPlugins
//@description: 创建插件
//@param: e model.EbpfPlugins
//@return: err error
func (ebpf *EbpfpluginsService) CreateEbpfPlugins(e ebpfplugins.EbpfPlugins) (err error) {
	err = global.GVA_DB.Create(&e).Error
	return err
}

//@author: [helight](https://github.com/hellight)
//@function: DeleteFileChunk
//@description: 删除插件
//@param: e model.EbpfPlugins
//@return: err error
func (ebpf *EbpfpluginsService) DeleteEbpfPlugins(e ebpfplugins.EbpfPlugins) (err error) {
	err = global.GVA_DB.Delete(&e).Error
	return err
}

//@author: [helight](https://github.com/helight)
//@function: UpdateEbpfPlugins
//@description: 更新插件
//@param: e *model.EbpfPlugins
//@return: err error
func (ebpf *EbpfpluginsService) UpdateEbpfPlugins(e *ebpfplugins.EbpfPlugins) (err error) {
	err = global.GVA_DB.Save(e).Error
	return err
}

//@author: [helight](https://github.com/hellight)
//@function: GetEbpfPlugins
//@description: 获取插件信息
//@param: id uint
//@return: err error, customer ebpfplugins.EbpfPlugins
func (ebpf *EbpfpluginsService) GetEbpfPlugins(id uint) (err error, customer ebpfplugins.EbpfPlugins) {
	err = global.GVA_DB.Where("id = ?", id).First(&customer).Error
	return
}

//@author: [helight](https://github.com/hellight)
//@function: GetEbpfPluginsInfoList
//@description: 分页获取插件列表
//@param: sysUserAuthorityID string, info request.PageInfo
//@return: err error, list interface{}, total int64
func (ebpf *EbpfpluginsService) GetEbpfPluginsInfoList(sysUserAuthorityID string, info request.PageInfo) (err error, list interface{}, total int64) {
	limit := info.PageSize
	offset := info.PageSize * (info.Page - 1)
	db := global.GVA_DB.Model(&ebpfplugins.EbpfPlugins{})

	var EbpfPluginsList []ebpfplugins.EbpfPlugins
	err = db.Count(&total).Error
	if err != nil {
		return err, EbpfPluginsList, total
	} else {
		err = db.Limit(limit).Offset(offset).Find(&EbpfPluginsList).Error
	}
	return err, EbpfPluginsList, total
}

//@author: [helight](https://github.com/hellight)
//@function: LoadEbpfPlugins
//@description: 加载插件到内核
//@param: e model.EbpfPlugins
//@return: err error
func (ebpf *EbpfpluginsService) LoadEbpfPlugins(e request.PluginInfo) (err error) {
	// todo
	// 1.状态判断，看是否已经加载到内核，判断State即可，避免重复下发
	db := global.GVA_DB.Model(&ebpfplugins.EbpfPlugins{})

	var plugin ebpfplugins.EbpfPlugins
	db.Where("id = ?", e.PluginId).First(&plugin)
	if plugin.State == 1 {
		return errors.New("already in use")
	}

	// 2.加载执行
	err = runSinglePlugin(plugin.PluginPath)
	if err != nil {
		return err
	}

	// 3.执行之后结果执行，成功还是失败
	plugin.State = 1 // 表示已经成功加载内核中运行
	err = global.GVA_DB.Save(plugin).Error

	return err
}

//@author: [helight](https://github.com/hellight)
//@function: UnloadEbpfPlugins
//@description: 删除插件
//@param: e model.EbpfPlugins
//@return: err error
func (ebpf *EbpfpluginsService) UnloadEbpfPlugins(e request.PluginInfo) (err error) {
	// todo
	// 1.判读是否已经加载，没有加载就无需卸载
	// 2.卸载执行
	// 3.执行之后结果执行，成功还是失败
	//e.State = 0 // 表示从内核中已经卸载
	db := global.GVA_DB.Model(&ebpfplugins.EbpfPlugins{})

	var plugin ebpfplugins.EbpfPlugins
	db.Where("id = ?", e.PluginId).First(&plugin)
	if plugin.State == 1 {
		plugin.State = 0
		killProcess(plugin.PluginPath)
		err = global.GVA_DB.Save(plugin).Error
	}

	return err
}

//@author: [helight](https://github.com/hellight)
//@function: GetEbpfPlugins
//@description: 获取插件信息
//@param: id uint
//@return: err error, customer ebpfplugins.EbpfPlugins
func (ebpf *EbpfpluginsService) GetEbpfPluginsContent(id uint) (err error, customer ebpfplugins.EbpfPlugins) {
	err = global.GVA_DB.Where("id = ?", id).First(&customer).Error
	if err != nil {
		return
	}
	data, err := ioutil.ReadFile(customer.PluginPath)
	customer.Content = string(data)
	return
}
