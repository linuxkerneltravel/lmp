package ebpfplugins

import (
	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"
	"go.uber.org/zap"
	"lmp/server/global"
	"lmp/server/model/common/request"
	"lmp/server/model/common/response"
	"lmp/server/model/ebpfplugins"
	ebpfpluginsRes "lmp/server/model/ebpfplugins/response"
	"lmp/server/utils"
	"net/http"
	"strconv"
	"strings"
	"time"
)

type EbpfPluginsApi struct{}

// @Tags EbpfPlugins
// @Summary 创建插件
// @Security ApiKeyAuth
// @accept application/json
// @Produce application/json
// @Param data body ebpfplugins.EbpfPlugins true "插件名"
// @Success 200 {string} string "{"success":true,"data":{},"msg":"创建成功"}"
// @Router /ebpf/ebpf [post]
func (e *EbpfPluginsApi) CreateEbpfPlugins(c *gin.Context) {
	var ebpfplugin ebpfplugins.EbpfPlugins
	_ = c.ShouldBindJSON(&ebpfplugin)
	if err := utils.Verify(ebpfplugin, utils.CustomerVerify); err != nil {
		response.FailWithMessage(err.Error(), c)
		return
	}
	// ebpfplugin.SysUserID = utils.GetUserID(c)
	// ebpfplugin.SysUserAuthorityID = utils.GetUserAuthorityId(c)
	if err := ebpfService.CreateEbpfPlugins(ebpfplugin); err != nil {
		global.GVA_LOG.Error("创建失败!", zap.Error(err))
		response.FailWithMessage("创建失败", c)
	} else {
		response.OkWithMessage("创建成功", c)
	}
}

// @Tags EbpfPlugins
// @Summary 删除插件
// @Security ApiKeyAuth
// @accept application/json
// @Produce application/json
// @Param data body ebpfplugins.EbpfPlugins true "插件ID"
// @Success 200 {string} string "{"success":true,"data":{},"msg":"删除成功"}"
// @Router /ebpf/ebpf [delete]
func (e *EbpfPluginsApi) DeleteEbpfPlugins(c *gin.Context) {
	var ebpfplugin ebpfplugins.EbpfPlugins
	_ = c.ShouldBindJSON(&ebpfplugin)
	if err := utils.Verify(ebpfplugin.GVA_MODEL, utils.IdVerify); err != nil {
		response.FailWithMessage(err.Error(), c)
		return
	}
	if err := ebpfService.DeleteEbpfPlugins(ebpfplugin); err != nil {
		global.GVA_LOG.Error("删除失败!", zap.Error(err))
		response.FailWithMessage("删除失败", c)
	} else {
		response.OkWithMessage("删除成功", c)
	}
}

// @Tags EbpfPlugins
// @Summary 更新插件信息
// @Security ApiKeyAuth
// @accept application/json
// @Produce application/json
// @Param data body ebpfplugins.EbpfPlugins true "插件ID, 插件信息"
// @Success 200 {string} string "{"success":true,"data":{},"msg":"更新成功"}"
// @Router /ebpf/ebpf [put]
func (e *EbpfPluginsApi) UpdateEbpfPlugins(c *gin.Context) {
	var ebpfplugin ebpfplugins.EbpfPlugins
	_ = c.ShouldBindJSON(&ebpfplugin)
	if err := utils.Verify(ebpfplugin.GVA_MODEL, utils.IdVerify); err != nil {
		response.FailWithMessage(err.Error(), c)
		return
	}
	if err := utils.Verify(ebpfplugin, utils.CustomerVerify); err != nil {
		response.FailWithMessage(err.Error(), c)
		return
	}
	if err := ebpfService.UpdateEbpfPlugins(&ebpfplugin); err != nil {
		global.GVA_LOG.Error("更新失败!", zap.Error(err))
		response.FailWithMessage("更新失败", c)
	} else {
		response.OkWithMessage("更新成功", c)
	}
}

// @Tags EbpfPlugins
// @Summary 获取单一插件信息
// @Security ApiKeyAuth
// @accept application/json
// @Produce application/json
// @Param data query ebpfplugins.EbpfPlugins true "插件ID"
// @Success 200 {string} string "{"success":true,"data":{},"msg":"获取成功"}"
// @Router /ebpf/ebpf [get]
func (e *EbpfPluginsApi) GetEbpfPlugins(c *gin.Context) {
	var ebpfplugin ebpfplugins.EbpfPlugins
	_ = c.ShouldBindQuery(&ebpfplugin)
	if err := utils.Verify(ebpfplugin.GVA_MODEL, utils.IdVerify); err != nil {
		response.FailWithMessage(err.Error(), c)
		return
	}
	err, data := ebpfService.GetEbpfPlugins(ebpfplugin.ID)
	if err != nil {
		global.GVA_LOG.Error("获取失败!", zap.Error(err))
		response.FailWithMessage("获取失败", c)
	} else {
		response.OkWithDetailed(ebpfpluginsRes.EbpfPluginsResponse{EbpfPlugins: data}, "获取成功", c)
	}
}

// @Tags EbpfPlugins
// @Summary 分页获取权限插件列表
// @Security ApiKeyAuth
// @accept application/json
// @Produce application/json
// @Param data query request.PageInfo true "页码, 每页大小"
// @Success 200 {string} string "{"success":true,"data":{},"msg":"获取成功"}"
// @Router /ebpf/ebpfList [get]
func (e *EbpfPluginsApi) GetEbpfPluginsList(c *gin.Context) {
	var pageInfo request.PageInfo
	_ = c.ShouldBindQuery(&pageInfo)
	if err := utils.Verify(pageInfo, utils.PageInfoVerify); err != nil {
		response.FailWithMessage(err.Error(), c)
		return
	}
	err, ebpfpluginList, total := ebpfService.GetEbpfPluginsInfoList(utils.GetUserAuthorityId(c), pageInfo)
	if err != nil {
		global.GVA_LOG.Error("获取失败!", zap.Error(err))
		response.FailWithMessage("获取失败"+err.Error(), c)
	} else {
		response.OkWithDetailed(response.PageResult{
			List:     ebpfpluginList,
			Total:    total,
			Page:     pageInfo.Page,
			PageSize: pageInfo.PageSize,
		}, "获取成功", c)
	}
}

// @Tags EbpfPlugins
// @Summary 加载插件到内核
// @Security ApiKeyAuth
// @accept application/json
// @Produce application/json
// @Param data body ebpfplugins.EbpfPlugins true "插件名"
// @Success 200 {string} string "{"success":true,"data":{},"msg":"创建成功"}"
// @Router /ebpf/ebpf [post]
func (e *EbpfPluginsApi) LoadEbpfPlugins(c *gin.Context) {
	var pluginInfo request.PluginInfo
	_ = c.ShouldBindJSON(&pluginInfo)
	if err := utils.Verify(pluginInfo, utils.PluginInfoVerify); err != nil {
		response.FailWithMessage(err.Error(), c)
		return
	}
	if err := ebpfService.LoadEbpfPlugins(pluginInfo, []string{}); err != nil {
		global.GVA_LOG.Error("加载失败!", zap.Error(err))
		response.FailWithMessage("加载失败", c)
	} else {
		response.OkWithMessage("加载成功", c)
	}
}

// @Tags EbpfPlugins
// @Summary 从内核卸载插件
// @Security ApiKeyAuth
// @accept application/json
// @Produce application/json
// @Param data body ebpfplugins.EbpfPlugins true "插件名"
// @Success 200 {string} string "{"success":true,"data":{},"msg":"创建成功"}"
// @Router /ebpf/ebpf [post]
func (e *EbpfPluginsApi) UnloadEbpfPlugins(c *gin.Context) {
	var pluginInfo request.PluginInfo
	_ = c.ShouldBindJSON(&pluginInfo)
	if err := utils.Verify(pluginInfo, utils.PluginInfoVerify); err != nil {
		response.FailWithMessage(err.Error(), c)
		return
	}

	if err := ebpfService.UnloadEbpfPlugins(pluginInfo); err != nil {
		global.GVA_LOG.Error("卸载失败!", zap.Error(err))
		response.FailWithMessage("卸载失败", c)
	} else {
		response.OkWithMessage("卸载成功", c)
	}
}

// @Tags EbpfPlugins
// @Summary 从内核获取插件
// @Security ApiKeyAuth
// @accept application/json
// @Produce application/json
// @Param data body ebpfplugins.EbpfPlugins true "插件名"
// @Success 200 {string} string "{"success":true,"data":{},"msg":"创建成功"}"
// @Router /ebpf/ebpf [post]
func (e *EbpfPluginsApi) GetEbpfPluginsContent(c *gin.Context) {
	var ebpfplugin ebpfplugins.EbpfPlugins
	_ = c.ShouldBindJSON(&ebpfplugin)
	if err := utils.Verify(ebpfplugin, utils.PluginInfoVerify); err != nil {
		response.FailWithMessage(err.Error(), c)
		return
	}

	err, data := ebpfService.GetEbpfPluginsContent(ebpfplugin.ID)
	if err != nil {
		global.GVA_LOG.Error("获取失败!", zap.Error(err))
		response.FailWithMessage("获取失败", c)
	} else {
		response.OkWithDetailed(ebpfpluginsRes.EbpfPluginsResponse{EbpfPlugins: data}, "获取成功", c)
	}
}

// @Tags EbpfPlugins
// @Summary 分页获取正在运行的插件列表
// @Security ApiKeyAuth
// @accept application/json
// @Produce application/json
// @Param data query request.PageInfo true "页码, 每页大小"
// @Success 200 {string} string "{"success":true,"data":{},"msg":"获取成功"}"
// @Router /ebpf/runningebpf [get]
func (e *EbpfPluginsApi) GetRunningEbpfPluginList(c *gin.Context) {
	var pageInfo request.PageInfo
	_ = c.ShouldBindQuery(&pageInfo)
	err, runningebpgplugins, total := ebpfService.GetRunningPluginsInfo(pageInfo)
	if err != nil {
		global.GVA_LOG.Error("获取失败!", zap.Error(err))
		response.FailWithMessage("获取失败"+err.Error(), c)
	} else {
		response.OkWithDetailed(response.PageResult{
			List:     runningebpgplugins,
			Total:    total,
			Page:     pageInfo.Page,
			PageSize: pageInfo.PageSize,
		}, "获取成功", c)
	}
}

// @Tags EbpfPlugins
// @Summary 获取单个ebpf程序的数据
// @Security ApiKeyAuth
// @accept application/json
// @Produce application/json
// @Success 200 {string} string "{"success":true,"data":{},"msg":"获取成功"}"
// @Router /ebpf/ebpfdata/:id [get]
func (e *EbpfPluginsApi) GetSinglePluginData(c *gin.Context) {
	type Result struct {
		List  interface{} `json:"list"`
		Total int         `json:"total"`
	}
	var id int
	id_str := c.Param("id")
	id, _ = strconv.Atoi(id_str)
	_ = c.ShouldBindQuery(&id)
	var upgrager = websocket.Upgrader{CheckOrigin: func(r *http.Request) bool {
		return true
	}}
	client, _ := upgrager.Upgrade(c.Writer, c.Request, nil)
	data_lenth := 0
	for {
		err, singleplugindata := ebpfService.FindRows(id)
		if err != nil {
			global.GVA_LOG.Error("获取失败", zap.Error(err))
			_ = client.WriteMessage(websocket.TextMessage, []byte("数据获取失败"))
			_ = client.Close()
			return
		} else {
			if data_lenth != len(singleplugindata) {
				err := client.WriteJSON(Result{
					List:  singleplugindata,
					Total: len(singleplugindata),
				})
				if err != nil {
					global.GVA_LOG.Error("写入json数据失败", zap.Error(err))
					_ = client.WriteMessage(websocket.TextMessage, []byte("写入json数据失败"))
					return
				}
				time.Sleep(time.Second * 2)
				data_lenth = len(singleplugindata)
			} else {
				if err := client.WriteMessage(websocket.TextMessage, []byte("数据加载完毕，无数据更新")); err != nil {
					global.GVA_LOG.Error("websocket message写入错误", zap.Error(err))
				}
				if err := client.Close(); err != nil {
					global.GVA_LOG.Error("websocket 关闭失败:", zap.Error(err))
				}
				return
			}
		}
	}
}

// @Tags EbpfPlugins
// @Summary 批量加载ebpf程序
// @Security ApiKeyAuth
// @accept application/json
// @Produce application/json
// @Success 200 {string} string "{"code":200,"msg":"获取成功"}"
// @Router /ebpf/batchloadebpf [post]
func (e *EbpfPluginsApi) BatchLoadEbpfplugins(c *gin.Context) {
	jsondata := make(map[string][]string)
	err := c.BindJSON(&jsondata)
	if err != nil {
		global.GVA_LOG.Error("json数据解析失败", zap.Error(err))
		response.FailWithMessage("json数据解释失败"+err.Error(), c)
	} else {
		for ebpfplugin, parameter := range jsondata {
			var e request.PluginInfo
			db := global.GVA_DB.Model(&ebpfplugins.EbpfPlugins{})
			var plugin ebpfplugins.EbpfPlugins
			db.Where("plugin_name=?", ebpfplugin).First(&plugin)
			e.PluginId = int(plugin.ID)
			err = ebpfService.LoadEbpfPlugins(e, parameter)
			if err != nil {
				global.GVA_LOG.Error("加载失败", zap.Error(err))
				response.FailWithMessage("加载失败"+err.Error(), c)
				continue
			} else {
				c.JSON(http.StatusOK, gin.H{
					"ebpfpluginname":   ebpfplugin,
					"commandparameter": strings.Join(parameter, " "),
					"code":             200,
					"msg":              "加载成功",
				})
			}
		}
	}
}
