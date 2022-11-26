## 文档系统环境

本文档系统使用 hugo 建设，可以在这里下载：[https://github.com/gohugoio/hugo/releases](https://github.com/gohugoio/hugo/releases)。

>我们使用 `exrended` 的版本，请直接下载使用这个版本。

例如：使用 0.89.4 的版本：
```
hugo_extended_0.89.4_Linux-64bit.tar.gz
```

## 文档系统部署

### 测试

1. 在 `lmp/docs` 的目录中直接运行 `hugo server` 命令。
2. 在浏览器中预览：http://localhost:1313/。
   
``` sh
➜  lmp git:(master) ✗ cd docs/
➜  docs git:(master) ✗ ls
archetypes/  config.toml  content/     data/        layouts/     readme.md    resources/   static/      themes/
➜  docs git:(master) ✗ hugo server
Start building sites …
hugo v0.89.2-63E3A5EB+extended darwin/amd64 BuildDate=2021-11-08T15:22:24Z VendorInfo=gohugoio

                   | EN | FR | ZH
-------------------+----+----+-----
  Pages            | 65 | 60 | 10
  Paginator pages  |  0 |  0 |  0
  Non-page files   | 22 |  0 |  0
  Static files     | 84 | 84 | 84
  Processed images |  0 |  0 |  0
  Aliases          |  1 |  0 |  0
  Sitemaps         |  2 |  1 |  1
  Cleaned          |  0 |  0 |  0

Built in 146 ms
Watching for changes in /Users/zhenwenxu/code/lmp/docs/{archetypes,content,data,layouts,static,themes}
Watching for config changes in /Users/zhenwenxu/code/lmp/docs/config.toml
Environment: "development"
Serving pages from memory
Running in Fast Render Mode. For full rebuilds on change: hugo server --disableFastRender
Web Server is available at http://localhost:1313/ (bind address 127.0.0.1)
Press Ctrl+C to stop
``` 

### 部署在lmp系统
1. 在 `lmp/docs` 的目录中直接运行 `hugo` 命令生成public目录。
2. 编辑nginx配置文件nginx.conf,修改文档地址，例如:/home/chen/lmp/docs/public/。
``` sh
sudo vim /etc/nginx/nginx.conf
server {
        listen       8088;
        server_name  localhost;
        #access_log  logs/host.access.log  main;
        root        /home/chen/lmp/docs/public/; #文档地址，是 hugo 编译之后的 public 目录

        location / {
            index  index.html index.htm;
        }
 }

```
## 文档编写
所有文档都在 `content` 中进行编写。
