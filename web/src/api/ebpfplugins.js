import service from '@/utils/request'
// @Tags SysApi
// @Summary 删除ebpf插件
// @Security ApiKeyAuth
// @accept application/json
// @Produce application/json
// @Param data body dbModel.ExaEbpfPlugin true "删除ebpf插件"
// @Success 200 {string} string "{"success":true,"data":{},"msg":"获取成功"}"
// @Router /ebpf/ebpf [post]
export const createExaEbpfPlugin = (data) => {
  return service({
    url: '/ebpf/ebpf',
    method: 'post',
    data
  })
}

// @Tags SysApi
// @Summary 更新ebpf插件信息
// @Security ApiKeyAuth
// @accept application/json
// @Produce application/json
// @Param data body dbModel.ExaEbpfPlugin true "更新ebpf插件信息"
// @Success 200 {string} string "{"success":true,"data":{},"msg":"获取成功"}"
// @Router /ebpf/ebpf [put]
export const updateExaEbpfPlugin = (data) => {
  return service({
    url: '/ebpf/ebpf',
    method: 'put',
    data
  })
}

// @Tags SysApi
// @Summary 创建ebpf插件
// @Security ApiKeyAuth
// @accept application/json
// @Produce application/json
// @Param data body dbModel.ExaEbpfPlugin true "创建ebpf插件"
// @Success 200 {string} string "{"success":true,"data":{},"msg":"获取成功"}"
// @Router /ebpf/ebpf [delete]
export const deleteExaEbpfPlugin = (data) => {
  return service({
    url: '/ebpf/ebpf',
    method: 'delete',
    data
  })
}

// @Tags SysApi
// @Summary 获取单一ebpf插件信息
// @Security ApiKeyAuth
// @accept application/json
// @Produce application/json
// @Param data body dbModel.ExaEbpfPlugin true "获取单一ebpf插件信息"
// @Success 200 {string} string "{"success":true,"data":{},"msg":"获取成功"}"
// @Router /ebpf/ebpf [get]
export const getExaEbpfPlugin = (params) => {
  return service({
    url: '/ebpf/ebpf',
    method: 'get',
    params
  })
}

// @Tags SysApi
// @Summary 获取全部ebpf插件列表
// @Security ApiKeyAuth
// @accept application/json
// @Produce application/json
// @Param data body modelInterface.PageInfo true "获取全部ebpf插件列表"
// @Success 200 {string} string "{"success":true,"data":{},"msg":"获取成功"}"
// @Router /ebpf/ebpfList [get]
export const getExaEbpfPluginList = (params) => {
  return service({
    url: '/ebpf/ebpfList',
    method: 'get',
    params
  })
}

// @Tags SysApi
// @Summary 加载ebpf插件
// @Security ApiKeyAuth
// @accept application/json
// @Produce application/json
// @Param data body modelInterface.PageInfo true "加载ebpf插件"
// @Success 200 {string} string "{"success":true,"data":{},"msg":"获取成功"}"
// @Router /ebpf/loadebpf [get]
export const LoadEbpfPlugins = (data) => {
  return service({
    url: '/ebpf/loadebpf',
    method: 'post',
    data
  })
}

// @Tags SysApi
// @Summary 加载ebpf插件
// @Security ApiKeyAuth
// @accept application/json
// @Produce application/json
// @Param data body modelInterface.PageInfo true "卸载ebpf插件"
// @Success 200 {string} string "{"success":true,"data":{},"msg":"获取成功"}"
// @Router /ebpf/unloadebpf [get]
export const UnloadEbpfPlugins = (data) => {
  return service({
    url: '/ebpf/unloadebpf',
    method: 'post',
    data
  })
}
