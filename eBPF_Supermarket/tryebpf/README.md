============欢迎使用eBPF初学者实践体验环境============

我们提供bpftrace、BCC等工具帮助大家体验eBPF~

======================目录结构========================

            请使用ebpfok用户登录本环境
        
        ~/README.md            介绍文档
        ~/test/                测试代码
        ~/framework/           eBPF常用框架
        ~/framework/bpftrace/  bpftrace
        ~/framework/bcc/       bcc
        ~/project/             社区开源项目
        ~/project/lmp/         LMP
        ~/project/eBPF         eBPF学习资料
        ~/docs/                本环境使用文档
    
=======================快速开始========================

使用bpftrace追踪文件打开:
sudo bpftrace -e 'BEGIN{printf("pid open\n");} 
    kprobe:do_sys_open{printf("%-8d%s\n",pid,str(arg1));}'

使用bcc tools追踪文件打开:
sudo python3 ~/framework/bcc/tools/opensnoop.py

=========================注意==========================

                   这是一个开放性环境
               请不要存储任何个人(隐私)数据！
               请及时将你的测试代码下载到本地！
           请爱护这个公共环境，不要做破坏性尝试！
                       感谢配合~
                  
=======================================================

                                             by LMP社区
