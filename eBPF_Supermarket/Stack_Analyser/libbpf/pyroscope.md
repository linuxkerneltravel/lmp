# 1.21

## server

```shell
git clone https://github.com/grafana/pyroscope.git
cd pyroscope
wget https://cdn.cypress.io/desktop/12.11.0/linux-x64/cypress.zip
unzip cypress.zip
tar -zcvf cypress.tar.gz cypress
yarn add cypress.tar.gz
make build
./pyroscope # server

./profilecli canary-exporter # run test agent in other shell
# port for the HTTP(S) server used for data ingestion and web UI
# address of the pyroscope server
# default http://localhost:4040

```

## agent

构建

```shell
git clone https://github.com/grafana/agent.git
make agent-flow
cd build
```

将以下配置保存到 config.river

```r
pyroscope.ebpf "instance" {
	forward_to     = [pyroscope.write.endpoint.receiver]
	targets_only   = false
	default_target = {"service_name" = "ebpf_profile"}
}

pyroscope.write "endpoint" {
	endpoint {
		url = "http://localhost:4040"
	}
}
```

运行

```shell
sudo ./grafana-agent-flow run config.river
/<path>/<to>/<pyroscope>/pyroscope
# port for the HTTP(S) server used for data ingestion and web UI
# address of the pyroscope server
# default http://localhost:4040
```

# 0.36

```shell
sudo ./pyroscope server
sudo ./pyroscope ebpf
# port for the HTTP(S) server used for data ingestion and web UI
# address of the pyroscope server
# default http://localhost:4040
```

# yarn install package from local folder

如果您想在本地文件夹中安装 yarn 包，您可以使用以下命令：

首先，需要将本地文件夹打包成 tar 压缩包。您可以使用以下命令：

```shell
tar -zcvf package_name.tar.gz /path/to/local/folder
```

然后，您可以使用以下命令在项目根目录中安装本地 tar 包：

```shell
yarn add file:/path/to/package_name.tar.gz
```

这将解压 tar 包并将其安装到项目的 node_modules 文件夹中。

请注意，安装本地 tar 包不是 yarn 的推荐方法，因此在生产环境中使用时请谨慎。