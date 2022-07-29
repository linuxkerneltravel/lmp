# 用法：1. self -l 显示tracepoint列表
# 2. self -d name1 name2 显示某个tracepoint的调用format
format_path='/sys/kernel/tracing/events'
if [ $1 == '-l' ]
then
    sudo perf list tracepoint # 需要加权限
elif [ $1 == '-d' ]
then
    path=$format_path/$2/$3
    sudo cat $path/format
fi
exit