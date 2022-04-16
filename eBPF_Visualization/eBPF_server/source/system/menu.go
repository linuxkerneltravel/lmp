package system

import (
	"lmp/server/global"
	"lmp/server/model/system"

	"github.com/pkg/errors"
	"gorm.io/gorm"
)

var BaseMenu = new(menu)

type menu struct{}

func (m *menu) TableName() string {
	return "sys_base_menus"
}

func (m *menu) Initialize() error {
	entities := []system.SysBaseMenu{
		{MenuLevel: 0, Hidden: false, ParentId: "0", Path: "dashboard", Name: "dashboard", Component: "view/dashboard/index.vue", Sort: 1, Meta: system.Meta{Title: "首页", Icon: "odometer"}},
		{MenuLevel: 0, Hidden: false, ParentId: "0", Path: "about", Name: "about", Component: "view/about/index.vue", Sort: 7, Meta: system.Meta{Title: "关于我们", Icon: "info-filled"}},
		{MenuLevel: 0, Hidden: false, ParentId: "0", Path: "admin", Name: "superAdmin", Component: "view/superAdmin/index.vue", Sort: 6, Meta: system.Meta{Title: "系统管理", Icon: "user"}},
		{MenuLevel: 0, Hidden: false, ParentId: "3", Path: "authority", Name: "authority", Component: "view/superAdmin/authority/authority.vue", Sort: 1, Meta: system.Meta{Title: "角色管理", Icon: "avatar"}},
		{MenuLevel: 0, Hidden: false, ParentId: "3", Path: "menu", Name: "menu", Component: "view/superAdmin/menu/menu.vue", Sort: 2, Meta: system.Meta{Title: "菜单管理", Icon: "tickets", KeepAlive: true}},
		{MenuLevel: 0, Hidden: false, ParentId: "3", Path: "api", Name: "api", Component: "view/superAdmin/api/api.vue", Sort: 3, Meta: system.Meta{Title: "api管理", Icon: "platform", KeepAlive: true}},
		{MenuLevel: 0, Hidden: false, ParentId: "3", Path: "user", Name: "user", Component: "view/superAdmin/user/user.vue", Sort: 4, Meta: system.Meta{Title: "用户管理", Icon: "coordinate"}},
		{MenuLevel: 0, Hidden: true, ParentId: "0", Path: "person", Name: "person", Component: "view/person/person.vue", Sort: 4, Meta: system.Meta{Title: "个人信息", Icon: "message"}},
		{MenuLevel: 0, Hidden: false, ParentId: "0", Path: "ebpf", Name: "ebpf", Component: "view/ebpf/index.vue", Sort: 2, Meta: system.Meta{Title: "eBPF插件管理", Icon: "management"}},
		{MenuLevel: 0, Hidden: false, ParentId: "9", Path: "listplugins", Name: "listplugins", Component: "view/ebpf/listplugins/listplugins.vue", Sort: 1, Meta: system.Meta{Title: "内核观察性组件", Icon: "avatar"}},
		{MenuLevel: 0, Hidden: false, ParentId: "9", Path: "funplugins", Name: "funplugins", Component: "view/ebpf/listplugins/listplugins.vue", Sort: 2, Meta: system.Meta{Title: "内核功能性组件", Icon: "avatar"}},
		{MenuLevel: 0, Hidden: false, ParentId: "9", Path: "analyplugins", Name: "analyplugins", Component: "view/ebpf/listplugins/listplugins.vue", Sort: 3, Meta: system.Meta{Title: "内核场景化分析组件", Icon: "avatar"}},
		{MenuLevel: 0, Hidden: false, ParentId: "3", Path: "dictionary", Name: "dictionary", Component: "view/superAdmin/dictionary/sysDictionary.vue", Sort: 5, Meta: system.Meta{Title: "字典管理", Icon: "notebook"}},
		{MenuLevel: 0, Hidden: true, ParentId: "3", Path: "dictionaryDetail/:id", Name: "dictionaryDetail", Component: "view/superAdmin/dictionary/sysDictionaryDetail.vue", Sort: 1, Meta: system.Meta{Title: "字典详情", Icon: "order"}},
		{MenuLevel: 0, Hidden: false, ParentId: "3", Path: "operation", Name: "operation", Component: "view/superAdmin/operation/sysOperationRecord.vue", Sort: 6, Meta: system.Meta{Title: "操作历史", Icon: "pie-chart"}},
		{MenuLevel: 0, Hidden: false, ParentId: "0", Path: "state", Name: "state", Component: "view/system/state.vue", Sort: 5, Meta: system.Meta{Title: "服务器状态", Icon: "cloudy"}},
	}
	if err := global.GVA_DB.Create(&entities).Error; err != nil { // 创建 model.User 初始化数据
		return errors.Wrap(err, m.TableName()+"表数据初始化失败!")
	}
	return nil
}

func (m *menu) CheckDataExist() bool {
	if errors.Is(global.GVA_DB.Where("path = ?", "autoCodeEdit/:id").First(&system.SysBaseMenu{}).Error, gorm.ErrRecordNotFound) { // 判断是否存在数据
		return false
	}
	return true
}
