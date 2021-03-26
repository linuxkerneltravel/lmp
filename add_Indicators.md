# 指标添加流程

这里只说明具体指标的添加过程，不分析整体的lmp处理。

项目处理流程是从main.go开始的，这里会直接调用路由处理。

```go
  r := routes.SetupRouter(settings.Conf.AppConfig.Mode)
```

路由是由routes目录下的routers.go来处理的。

这里自定义了一个路由做路由处理，访问localhost：8080进行访问，static下的file，index.html。

```go
func SetupRouter(mode string) *gin.Engine {
	if mode == gin.ReleaseMode {
		gin.SetMode(gin.ReleaseMode)
	}

r := gin.New()
r.Use(cors())
r.Use(logger.GinLogger(), logger.GinRecovery(true))
r.Use(static.Serve("/", static.LocalFile("static", false)))
r.StaticFS("/static", http.Dir("static/"))

r.GET("/ping", func(c *gin.Context) {
	c.String(http.StatusOK, "pong")
})

r.GET("/allplugins", controllers.PrintAllplugins)
r.POST("/data/collect", controllers.Collect)

// for tianjin
//r.GET("/irq_delay", controllers.QueryIRQ)
//r.GET("/cpu_utilize", controllers.QueryCpuUtilize)
//r.GET("/pick_next", controllers.QueryPickNext)
//r.GET("/task_switch", controllers.QueryTaskSwitch)
//r.GET("/harddisk_readwritetime", controllers.QueryHardDiskReadWriteTime)
//r.GET("/water_mark", controllers.QueryWaterMark)

r.NoRoute(func(c *gin.Context) {
	c.Header("Content-Type", "text/html,charset=utf-8")
	c.File(fmt.Sprintf("%s/index.html", "static"))
})

return r

}
```

## index.html

加载到静态页面index.html。这个页面位于static下，static这里保存一些静态信息。

```html
 <form action="/data/collect" method="post">
            <input type="checkbox" name="cpuutilize" value="true">cpuutilize&nbsp;&nbsp;&nbsp;
            <input type="checkbox" name="irq" value="true">irq&nbsp;&nbsp;&nbsp;
            <input type="checkbox" name="memusage" value="true">memusage&nbsp;&nbsp;&nbsp;
            <input type="checkbox" name="picknexttask" value="true">picknexttask&nbsp;&nbsp;&nbsp;
            <br>
            <input type="checkbox" name="runqlen" value="true">runqlen&nbsp;&nbsp;&nbsp;
            <input type="checkbox" name="vfsstat" value="true">vfsstat&nbsp;&nbsp;&nbsp;
            <input type="checkbox" name="dcache" value="true">dcache&nbsp;
            <label for="other"></label>
            <input type="text" name="collecttime" value="-1">
            <br>
            <br>
            <br>
            <input id="sub" type="submit" value="submit">
 </form>
```

这里的做前端的处理，可以在form表单里加入自己的指标选框。表单提交后转到/data/collect，这里继续做路由处理。

## Collect

在routers.go中`r.POST("/data/collect", controllers.Collect)`这里进行了处理

第二个参数是我们需要执行的动作。这里跳转到了controllers这个包下的Collect函数

```go
func Collect(c *gin.Context) {
	m := fillFrontMessage(c)
...
}
```

执行fillFrontMessage函数

这个函数做表单数据的提交处理，在这里加上我们的处理函数，append第二个参数是执行文件路径，这里指需要修改字符串名为自己的Python文件名即可

```go
func fillFrontMessage(c *gin.Context) models.ConfigMessage {
	var m models.ConfigMessage

	if v, ok := c.GetPostForm("cpuutilize"); ok && v == "true" {
		m.Cpuutilize = true
		m.BpfFilePath = append(m.BpfFilePath, settings.Conf.PluginConfig.Path+"cpuutilize.py")
	} else {
		m.Cpuutilize = false
	}
 ...   
}
```

## pluginparam.go

m是一个models.ConfigMessage类型的结构体变量，位于models目录下的pluginparam.go中

在里面加上自己的指标，也就是由前端表单传过来的点选框对应的name，name名要与json后面的参数对应                                                                                                                                                                                                                                                                                                                                                                                                               

```go
type ConfigMessage struct {
	Cpuutilize   bool `json:"cpuutilize"`
	Irq          bool `json:"irq"`
	Memusage     bool `json:"memusage"`
	Picknexttask bool `json:"picknexttask"`
	Runqlen      bool `json:"runqlen"`
	Vfsstat      bool `json:"vfsstat"`
	Dcache       bool `json:"dcache"`

	// Store the config above to the 'BpfFilePath'
	BpfFilePath []string `json:"bpfFilePath"`
	// time
	CollectTime int `json:"collecttime"`
}
```

## plugins

Python文件是我们的指标文件，可以参照api.py编写，也可以参照其他指标编写。

里面的这一句是写入操作，对应db_modules.py这个文件，调用的是Python操作influxdb

```
write2db(data_struct,test_data,client)
```

对数据库的查询操作这里需要访问dao层的influxdb.go这个文件是数据库初始化和创建。

## controllers/tj.go

查询操作在data.go中

我们要查询自己的指标要在controllers下的tj.go中添加自己的函数

```go
func QueryIRQ(c *gin.Context) {
	res, err := logic.DoQueryIRQ()
	if err != nil {
		zap.L().Error("ERROR in QueryIRQ():", zap.Error(err))
		ResponseError(c, CodeServerBusy)
		return
	}

	ResponseSuccess(c, res)
}

```

## logic/tj.go

它调用了logic层的你自己定义的函数,在tj.go中

```go
func DoQueryIRQ() (res []client.Result, err error) {
	// 调用dao层influxdb API
	res, err = influxdb.QueryDB(`select last("duration") from "irq"`)
	if err != nil {
		zap.L().Error("ERROR in DoQueryIRQ():", zap.Error(err))
		return nil, err
	}
	return
}


func DoQueryCpuUtilize() (res []client.Result, err error) {
	res, err = influxdb.QueryDB(`select last("perce") from "cpuutilize"`)
	if err != nil {
		zap.L().Error("ERROR in DoQueryIRQ():", zap.Error(err))
		return nil, err
	}
	return
}
```

自己定义一个函数，这里需要看你提取的指标在python文件中的fields是duration（延时）还是perce（百分率）。

## test/grafana-JSON/lmp.json

到这里我们还需要做grafana的panel面板的添加，在test目录下的grafana-JSON下的lmp.json这个文件中,找到这段话。

```json
    {
      "aliasColors": {},
      "bars": false,
      "dashLength": 10,
      "dashes": false,
      "datasource": null,
      "fieldConfig": {
        "defaults": {
          "custom": {}
        },
        "overrides": []
      },
      "fill": 1,
      "fillGradient": 0,
      "gridPos": {
        "h": 8,
        "w": 12,
        "x": 0,
        "y": 17
      },
      "hiddenSeries": false,
      "id": 6,
      "legend": {
        "avg": false,
        "current": false,
        "max": false,
        "min": false,
        "show": true,
        "total": false,
        "values": false
      },
      "lines": true,
      "linewidth": 1,
      "nullPointMode": "null",
      "percentage": false,
      "pluginVersion": "7.1.3",
      "pointradius": 2,
      "points": false,
      "renderer": "flot",
      "seriesOverrides": [],
      "spaceLength": 10,
      "stack": false,
      "steppedLine": false,
      "targets": [
        {
          "groupBy": [
            {
              "params": [
                "$__interval"
              ],
              "type": "time"
            },
            {
              "params": [
                "null"
              ],
              "type": "fill"
            }
          ],
          "orderByTime": "ASC",
          "policy": "default",
          "query": "SELECT \"duration\" FROM \"irq\" ",
          "rawQuery": true,
          "refId": "A",
          "resultFormat": "time_series",
          "select": [
            [
              {
                "params": [
                  "value"
                ],
                "type": "field"
              },
              {
                "params": [],
                "type": "mean"
              }
            ]
          ],
          "tags": []
        }
      ],
      "thresholds": [],
      "timeFrom": null,
      "timeRegions": [],
      "timeShift": null,
      "title": "IRQ",
      "tooltip": {
        "shared": true,
        "sort": 0,
        "value_type": "individual"
      },
      "type": "graph",
      "xaxis": {
        "buckets": null,
        "mode": "time",
        "name": null,
        "show": true,
        "values": []
      },
      "yaxes": [
        {
          "format": "short",
          "label": null,
          "logBase": 1,
          "max": null,
          "min": null,
          "show": true
        },
        {
          "format": "short",
          "label": null,
          "logBase": 1,
          "max": null,
          "min": null,
          "show": true
        }
      ],
      "yaxis": {
        "align": false,
        "alignLevel": null
      }
    },

```

这是面板配置，你需要修改的是

面板id 	        "id": 6

查询语句		"query": "SELECT \"duration\" FROM \"irq\" ",

面板标题		"title": "IRQ",

把json重新import到grafana中就可以得到数据了。

