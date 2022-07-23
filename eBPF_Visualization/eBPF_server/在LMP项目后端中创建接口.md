# 如何在lmp项目的后端添加一个接口

​			lmp项目采用gin作为后端框架，使用了开源的gin-vue-admin作为开发模板，以此为基础进行后端的开发。后端项目的文件分层结构如下图所示:

### **server项目结构**

```shell
├── api
│   └── v1
├── config
├── core
├── docs
├── global
├── initialize
│   └── internal
├── middleware
├── model
│   ├── request
│   └── response
├── packfile
├── resource
│   ├── excel
│   ├── page
│   └── template
├── router
├── service
├── source
└── utils
    ├── timer
    └── upload
```

| 文件夹       | 说明                  | 描述                                                         |
| ------------ | --------------------- | ------------------------------------------------------------ |
| `api`        | api层                 | api层                                                        |
| `--v1`       | v1版本接口            | v1版本接口                                                   |
| `config`     | 配置包                | config.yaml对应的配置结构体                                  |
| `core`       | 核心文件              | 核心组件(zap, viper, server)的初始化                         |
| `docs`       | swagger文档目录       | swagger文档目录                                              |
| `global`     | 全局对象              | 全局对象                                                     |
| `initialize` | 初始化                | router,redis,gorm,validator, timer的初始化                   |
| `--internal` | 初始化内部函数        | gorm 的 longger 自定义,在此文件夹的函数只能由 `initialize` 层进行调用 |
| `middleware` | 中间件层              | 用于存放 `gin` 中间件代码                                    |
| `model`      | 模型层                | 模型对应数据表                                               |
| `--request`  | 入参结构体            | 接收前端发送到后端的数据。                                   |
| `--response` | 出参结构体            | 返回给前端的数据结构体                                       |
| `packfile`   | 静态文件打包          | 静态文件打包                                                 |
| `resource`   | 静态资源文件夹        | 负责存放静态文件                                             |
| `--excel`    | excel导入导出默认路径 | excel导入导出默认路径                                        |
| `--page`     | 表单生成器            | 表单生成器 打包后的dist                                      |
| `--template` | 模板                  | 模板文件夹,存放的是代码生成器的模板                          |
| `router`     | 路由层                | 路由层                                                       |
| `service`    | service层             | 存放业务逻辑问题                                             |
| `source`     | source层              | 存放初始化数据的函数                                         |
| `utils`      | 工具包                | 工具函数封装                                                 |
| `--timer`    | timer                 | 定时器接口封装                                               |
| `--upload`   | oss                   | oss接口封装                                                  |

### **添加接口所涉及的文件夹如下:**

```shell
├── api
│   └── v1
├── initialize
│   └── internal
├── router
├── service
```

### **添加一个接口的核心步骤:**

1. 在服务层编写接口逻辑(service)。
2. 在api层编写入口(api)。
3. 在路由层进行注册，实现跟外部的对接(router)。
4. 将接口添加到初始化列表中(initialize)。

# test接口案例

***服务层:***

​			1、在service目录下创建一个名为test的下级目录用于存放test的逻辑部分的程序，目录结构如下:

```
├── test
│   └── servicetest.go
|   └── enter.go
```

​			2、在service/test/servicetest.go中编写业务逻辑:

```go
package test

import "fmt"

type ServiceTest struct{} //创建

func (t *ServiceTest) CreateApis() {
	fmt.Printf("Create Apis") //业务逻辑
}
```

​			3、在service/test/enter.go中注册业务逻辑

```go
package test

type ServiceGroup struct {
	ServiceTest
}

```

​			4、在service/enter.go中注册编写好的TestApi

```go
package service

import (
	"lmp/server/service/ebpfplugins"
	"lmp/server/service/system"
	"lmp/server/service/test"
)

type ServiceGroup struct {
	SystemServiceGroup system.ServiceGroup
	EbpfServiceGroup   ebpfplugins.ServiceGroup
	Test               test.ServiceTest                  //新增的组
}

var ServiceGroupApp = new(ServiceGroup)
```

***API层:***

​			1、在api/v1目录下创建一个名为test的下级目录用于存放test的api程序,目录结构如下:

```she
├── test
│   └── apitest.go
|   └── enter.go
```

​		    2、编写api/v1/test/enter.go入口文件

```go
package test

import "lmp/server/service"

type ApiGroup struct {
	ApiTest
}
var testapiservice=service.ServiceGroupApp.ServiceTest
```

​			3、编写api/v1/test/apitest.go文件

```go
package test

import (
	"github.com/gin-gonic/gin"
	"lmp/server/model/common/response"
)

type ApiTest struct{}

func (t *ApiTest) CreateApi(c *gin.Context) {
	testapiservice.CreateApis()
    c.String(200,"Test Success!")
}

```

​			4、将api注册进api/v1/enter.go

```go
package v1

import (
	"lmp/server/api/v1/ebpfplugins"
	"lmp/server/api/v1/system"
	"lmp/server/api/v1/test"
)

type ApiGroup struct {
	SystemApiGroup      system.ApiGroup
	EbpfPluginsApiGroup ebpfplugins.ApiGroup
	ApiTestGroup test.ApiGroup                      //新增的api组
}

var ApiGroupApp = new(ApiGroup)
```

***路由层:***

​			1、在router目录下创建一个名为test的下级目录用于存放test的路由组程序,目录结构如下:

```
├── test
│   └── routertest.go
|   └── enter.go
```

​			2、在test/routertest.go中创建结构体，并创建新的路由组

```go
package test

import (
	"github.com/gin-gonic/gin"
	v1 "lmp/server/api/v1"
)

type RouterTest struct{}

func (r *RouterTest) InitRouterTest(Router *gin.RouterGroup) {
	RouterTestGroup := Router.Group("routertest")
	api := v1.ApiGroupApp.ApiTestGroup.ApiTest //调用逻辑层中创建的对象
	{
		RouterTestGroup.GET("TestNewRouter", api.CreateApi)
	} //将post方法写在作用域内
}
```

​			3、在test/enter.go中注册路由组

```go
package test

type RouterGroup struct {
	RouterTest
}

```

​			4、将路由组注册到router/enter.go的总路由组中

```go
package router

import (
	"lmp/server/router/ebpfplugins"
	"lmp/server/router/system"
	"lmp/server/router/test"
)

type RouterGroup struct {
	System      system.RouterGroup
	EbpfPlugins ebpfplugins.RouterGroup
	RouterTest  test.RouterGroup            //新增的路由组
}

var RouterGroupApp = new(RouterGroup)
```

***初始化注册:***

​			1、打开initialize/router.go,将新的路由添加到初始化列表中。**在第44行创建test的路由组实例，在第52行注册test路由。**

```go
package initialize

import (
	"net/http"

	_ "lmp/server/docs"
	"lmp/server/global"
	"lmp/server/middleware"
	"lmp/server/router"

	"github.com/gin-gonic/gin"
	"github.com/swaggo/gin-swagger"
	"github.com/swaggo/gin-swagger/swaggerFiles"
)

// 初始化总路由

func Routers() *gin.Engine {
	Router := gin.Default()

	// 如果想要不使用nginx代理前端网页，可以修改 web/.env.production 下的
	// VUE_APP_BASE_API = /
	// VUE_APP_BASE_PATH = http://localhost
	// 然后执行打包命令 npm run build。在打开下面4行注释
	// Router.LoadHTMLGlob("./dist/*.html") // npm打包成dist的路径
	// Router.Static("/favicon.ico", "./dist/favicon.ico")
	// Router.Static("/static", "./dist/assets")   // dist里面的静态资源
	// Router.StaticFile("/", "./dist/index.html") // 前端网页入口页面

	Router.StaticFS(global.GVA_CONFIG.Local.Path, http.Dir(global.GVA_CONFIG.Local.Path)) // 为用户头像和文件提供静态地址
	// Router.Use(middleware.LoadTls())  // 打开就能玩https了
	global.GVA_LOG.Info("use middleware logger")
	// 跨域，如需跨域可以打开下面的注释
	// Router.Use(middleware.Cors()) // 直接放行全部跨域请求
	//Router.Use(middleware.CorsByRules()) // 按照配置的规则放行跨域请求
	global.GVA_LOG.Info("use middleware cors")
	Router.GET("/swagger/*any", ginSwagger.WrapHandler(swaggerFiles.Handler))
	global.GVA_LOG.Info("register swagger handler")
	// 方便统一添加路由组前缀 多服务器上线使用

	// 获取路由组实例
	systemRouter := router.RouterGroupApp.System
	ebpfRouter := router.RouterGroupApp.EbpfPlugins
	testRouter := router.RouterGroupApp.RouterTest

	PublicGroup := Router.Group("")
	{
		// 健康监测
		PublicGroup.GET("/health", func(c *gin.Context) {
			c.JSON(200, "ok")
		})
		testRouter.InitRouterTest(PublicGroup)
	}
	{
		systemRouter.InitBaseRouter(PublicGroup) // 注册基础功能路由 不做鉴权
		systemRouter.InitInitRouter(PublicGroup) // 自动初始化相关
	}
	PrivateGroup := Router.Group("")
	PrivateGroup.Use(middleware.JWTAuth()).Use(middleware.CasbinHandler())
	{
		systemRouter.InitApiRouter(PrivateGroup)                 // 注册功能api路由
		systemRouter.InitJwtRouter(PrivateGroup)                 // jwt相关路由
		systemRouter.InitUserRouter(PrivateGroup)                // 注册用户路由
		systemRouter.InitMenuRouter(PrivateGroup)                // 注册menu路由
		systemRouter.InitSystemRouter(PrivateGroup)              // system相关路由
		systemRouter.InitCasbinRouter(PrivateGroup)              // 权限相关路由
		systemRouter.InitAutoCodeRouter(PrivateGroup)            // 创建自动化代码
		systemRouter.InitAuthorityRouter(PrivateGroup)           // 注册角色路由
		systemRouter.InitSysDictionaryRouter(PrivateGroup)       // 字典管理
		systemRouter.InitAutoCodeHistoryRouter(PrivateGroup)     // 自动化代码历史
		systemRouter.InitSysOperationRecordRouter(PrivateGroup)  // 操作记录
		systemRouter.InitSysDictionaryDetailRouter(PrivateGroup) // 字典详情管理

		ebpfRouter.InitEbpfRouter(PrivateGroup) // ebpf路由
	}

	InstallPlugin(PublicGroup, PrivateGroup) // 安装插件

	global.GVA_LOG.Info("router register success")
	return Router
}

```

***测试是否正确添加接口***

```bash
cd ~/lmp/eBPF_Visualization/eBPF_server     #进入web后端目录
make    #编译
sudo ./lmp-server  #启动后端服务
```

```bash
...
[GIN-debug] GET    /uploads/file/*filepath   --> github.com/gin-gonic/gin.(*RouterGroup).createStaticHandler.func1 (3 handlers)
[GIN-debug] HEAD   /uploads/file/*filepath   --> github.com/gin-gonic/gin.(*RouterGroup).createStaticHandler.func1 (3 handlers)
[lmp/server]2022/07/23 - 23:04:11.636   info    /home/yuemeng/lmp/eBPF_Visualization/eBPF_server/initialize/router.go:32        use middleware logger
[lmp/server]2022/07/23 - 23:04:11.636   info    /home/yuemeng/lmp/eBPF_Visualization/eBPF_server/initialize/router.go:36        use middleware cors
[GIN-debug] GET    /swagger/*any             --> github.com/swaggo/gin-swagger.CustomWrapHandler.func1 (3 handlers)
[lmp/server]2022/07/23 - 23:04:11.636   info    /home/yuemeng/lmp/eBPF_Visualization/eBPF_server/initialize/router.go:38        register swagger handler
[GIN-debug] GET    /health                   --> lmp/server/initialize.Routers.func1 (3 handlers)
[GIN-debug] GET    /routertest/TestNewRouter --> lmp/server/api/v1/test.(*ApiTest).CreateApi-fm (3 handlers)   #在打印的日志信息中找到test接口的信息，说明后端接口正确添加
[GIN-debug] POST   /base/login               --> lmp/server/api/v1/system.(*BaseApi).Login-fm (3 handlers)
...
```

***API测试***

![Screenshot_1](https://user-images.githubusercontent.com/78520005/180611482-0459ce6f-4a31-4a69-b405-dac438ab2771.png)


接口测试通过！
