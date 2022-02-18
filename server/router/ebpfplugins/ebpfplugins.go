package ebpfplugins

import (
	v1 "lmp/server/api/v1"
	"lmp/server/middleware"

	"github.com/gin-gonic/gin"
)

type EbpfpluginsRouter struct{}

func (e *EbpfpluginsRouter) InitEbpfRouter(Router *gin.RouterGroup) {
	ebpfRouter := Router.Group("ebpf").Use(middleware.OperationRecord())
	ebpfRouterWithoutRecord := Router.Group("ebpf")
	ebpfApi := v1.ApiGroupApp.EbpfPluginsApiGroup.EbpfPluginsApi
	{
		ebpfRouter.POST("ebpf", ebpfApi.CreateEbpfPlugins)   // 创建插件
		ebpfRouter.PUT("ebpf", ebpfApi.UpdateEbpfPlugins)    // 更新插件
		ebpfRouter.DELETE("ebpf", ebpfApi.DeleteEbpfPlugins) // 删除插件

		ebpfRouter.POST("loadebpf", ebpfApi.LoadEbpfPlugins)     // 加载插件到内核
		ebpfRouter.POST("unloadebpf", ebpfApi.UnloadEbpfPlugins) // 从内核卸载插件
	}
	{
		ebpfRouterWithoutRecord.GET("ebpf", ebpfApi.GetEbpfPlugins)                // 获取单一插件信息
		ebpfRouterWithoutRecord.GET("ebpfList", ebpfApi.GetEbpfPluginsList)        // 获取插件列表
		ebpfRouterWithoutRecord.POST("ebpfContent", ebpfApi.GetEbpfPluginsContent) // 获取插件列表
	}
}
