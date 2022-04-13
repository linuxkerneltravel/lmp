package request

// PageInfo Paging common input parameter structure
type PageInfo struct {
	Page     int `json:"page" form:"page"`         // 页码
	PageSize int `json:"pageSize" form:"pageSize"` // 每页大小
}

type PluginInfo struct {
	PluginId int `json:"id" form:"ID"`
	//PluginName string `json:"pluginName" form:"pluginName"`
	//PluginState int `json:"pluginState" form:"pluginState"`
	//PLuginPath string `json:"pLuginPath" form:"pLuginPath"`
	//CollectTime int `json:"collectTime" form:"collectTime"`
}

// GetById Find by id structure
type GetById struct {
	ID float64 `json:"id" form:"id"` // 主键ID
}

func (r *GetById) Uint() uint {
	return uint(r.ID)
}

type IdsReq struct {
	Ids []int `json:"ids" form:"ids"`
}

// GetAuthorityId Get role by id structure
type GetAuthorityId struct {
	AuthorityId string `json:"authorityId" form:"authorityId"` // 角色ID
}

type Empty struct{}
