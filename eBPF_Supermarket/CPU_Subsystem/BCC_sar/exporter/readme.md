本目录下的app.py可以读取json文件并将其映射到某个端口的路由上。当grafana配置了相应的读取策略后，我们就可以在Grafana中创建我们想要的图形，以可视化的方式展示数据。

注意：如果要对app.py做改动，应当保持访问接口后返回的数据是json格式的文本数据，且其格式与本目录下metrics.json文件的格式一致。

启动方式：
```shell
python3 app.py
```

在启动后，本程序将在7000端口产生数据。

metrics.json文件的格式如下：
```python
{
    "time": 1665391755.7896347,
    "state": "wait-swapper/0",
    "pid": 64126
},
{
    "time": 1665391755.7897527,
    "state": "run",
    "pid": 64126
},
{
    "time": 1665391755.789883,
    "state": "sleep-ep_poll",
    "pid": 64126
},
{
    "time": 1665391755.8711462,
    "state": "wait-swapper/0",
    "pid": 64126
},
{
    "time": 1665391755.8711557,
    "state": "run",
    "pid": 64126
},
```
其中time指的是**状态开始**的时间(单位：秒)，state指的是状态的名称，pid指的是发生状态变化的程序。state主要包括以下类型：

* run: 程序处于运行的状态
* sleep-{block_func}: 程序处于睡眠的状态，后面的{block_func}指的是程序阻塞的函数名
* wait-{process_comm}: 程序处于RUNNING状态，但未在CPU上运行，正在等待被调度上CPU。程序wait之前的状态一般是run或者sleep（被唤醒），若为sleep，则之后的{process_comm}记录的是唤醒该进程的进程名称(comm)。 

metrics.json的获取方式：
```shell
cd ~/LMP/eBPF_Supermarket/CPU_Subsystem/BCC_sar/src/wakeup
sudo python3 wakeup.py -t json -p 1234
```
这样就可以产生最近三秒内pid=1234的进程的状态切换JSON数据

注意：在运行app.py时，也允许使用wakeup.py更新metrics.json，只需要在Grafana界面上点击刷新即可看到最新的数据。

后续计划：
* 简化生成的数据，使得能够连续向Grafana传输数据
* 调整时间记录，以与Grafana的时间显示匹配
* 分析Linux原生的调度策略，之后可以根据需求重写调度器？