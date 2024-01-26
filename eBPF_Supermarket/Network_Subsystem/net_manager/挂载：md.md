挂载：

```
sudo ./xdp_loader -d docker0 -S
sudo ./xdp_loader -d docker0 --progname filter_ethernet_drop -S
sudo ./xdp_loader -d docker0 --progname xdp_redirect_func -S
```

加载规则

```
sudo ./xacladm pass_mac docker0 1 mac
sudo ./xacladm pass_mac docker0 1 mac
sudo ./xacladm drop_mac docker0 1 mac
sudo ./xacladm drop_mac docker0 1 mac
sudo ./xacladm load docker0 ./conf.d/mac_load.conf
```

卸载

```
sudo xdp-loader unload docker0 --all
```

