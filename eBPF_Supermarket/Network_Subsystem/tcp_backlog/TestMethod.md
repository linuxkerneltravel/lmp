## 测试方法

1.编译并运行tcp_establish

```bash
sudo make && ./tcp_backlog
```

2.编译并运行测试服务端程序

```bash
gcc test_server.c -o test_server && ./test_server
```

3.查看test_server的端口号，并访问

- 通过开启终端窗口运行`curl localhost:23456`

- 或通过其他压测工具

4.查看输出结果

```bash
sudo cat /sys/kernel/debug/tracing/trace_pipe
```