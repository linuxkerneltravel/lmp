# 前端页面运行

## web 工程开发测试
```
npm install
```

### Compiles and hot-reloads for development
```
npm run serve
```

### Run your tests
```
npm run test
```

### Lints and fixes files
```
npm run lint
```

### Customize configuration
See [Configuration Reference](https://cli.vuejs.org/config/).

## web 编译部署
### Compiles and minifies for production
```
npm run build
```
### 修改 nginx 配置文件
1. 修改部署文件路径： 
修改 nginx.conf 文件中的这个地方
```
root        /Users/helightxu/lmp/LMP/web/dist;
```
1. 拷贝 nginx.conf 文件到 nginx 的配置目录。
``` sh
cp nginx.conf /opt/homebrew/etc/nginx
```
1. 测试配置文件
``` sh
nginx -t
nginx: the configuration file /opt/homebrew/etc/nginx/nginx.conf syntax is ok
nginx: configuration file /opt/homebrew/etc/nginx/nginx.conf test is successful
```
1. 重新加载配置文件
``` sh
nginx -s reload
```
1. 后端程序运行，后端运行在 8888 端口，看 nginx 的配置文件
``` sh
./server
```
1. 浏览器登录页面
http://localhost:8080/
   
## 整理代码结构
``` lua
web
├── public -- public
|   ├── favicon.ico -- ico
|   └── index.html -- index
├── src   -- 源代码
│   ├── api  -- 所有请求
│   ├── assets  --  主题 字体等静态资源
|   ├── components -- components组件
|   ├── core -- gva抽离的一些前端资源
|   |   ├── config.js -- 配置文件
|   |   └── element_lazy.js -- elementt按需引入文件
|   |   └── gin-vue-admin.js -- gva前端控制库
|   ├── directive -- 公用方法 
|   ├── mixins -- 公用方法
|   ├── router -- 路由权限
|   ├── store -- store 
|   |   ├── modules -- modules 
|   |   |   ├── dictionary.js -- 动态路由
|   |   |   ├── router.js -- 路由
|   |   |   └── user.js -- 用户权限菜单过滤
|   |   ├── getters.js -- getters
|   |   └── index.js -- index
|   ├── styles -- css
|   ├── utils -- utils 组件
|   ├── view -- 主要view代码
|   |   ├── about -- 关于我们
|   |   ├── dashboard -- 面板
|   |   ├── error -- 错误
|   |   ├── example --上传案例
|   |   ├── iconList -- icon列表
|   |   ├── init -- 初始化数据  
|   |   |   ├── index -- 新版本
|   |   |   ├── init -- 旧版本
|   |   ├── layout  --  layout约束页面 
|   |   |   ├── aside -- 
|   |   |   ├── bottomInfo -- bottomInfo
|   |   |   ├── screenfull -- 全屏设置
|   |   |   ├── setting    -- 系统设置
|   |   |   └── index.vue -- base 约束
|   |   ├── login --登录 
|   |   ├── person --个人中心 
|   |   ├── superAdmin -- 超级管理员操作
|   |   ├── system -- 系统检测页面
|   |   ├── systemTools -- 系统配置相关页面
|   |   └── routerHolder.vue -- page 入口页面 
│   ├── App.vue  -- 入口页面
│   ├── main.js  -- 入口文件 加载组件 初始化等
│   └── permission.js  -- 跳转
├── build.config.js  -- 环境变量build配置
├── .babelrc    -- babel-loader 配置
├── .travis.yml -- 自动化CI配置
├── vue.config.js  -- vue-cli 配置
└── package.json  -- package.json
```