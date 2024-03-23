该文件夹存放本项目可视化前端代码。
- 火焰图
  - 支持生成符合火焰图格式的文件，然后借助[FlameGraph](https://github.com/brendangregg/FlameGraph)生成火焰图
- 前端可视化框架采用grafana + prometheus
  - 基于时间序列的数据呈现形式


lmp中的可视化代码，metrics在go代码中定义，那么针对不用类型
的数据呈现形式，是否需要多次定义metrics？？？