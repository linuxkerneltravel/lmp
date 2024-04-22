#!/bin/sh

MAGIC_EYES_CLI_INSTALL_DIR=$(dirname $(realpath $0))

check_conditions() {
	# 判断python3是否存在
	if /usr/bin/env python3 -V > /dev/null; then
		echo "python 已安装"
	else
		echo "python 未安装"
		return 1
	fi
	# 进入python venv环境
	if . ./venv/bin/activate; then
		echo "成功进入venv环境"
	else
		echo "进入venv环境失败"
		return 1
	fi
	# 使用pip列出所有已安装的包，并搜索argcomplete，判断是否argcomplete是否存在
	if pip list --verbose | grep -q "argcomplete"; then
		echo "argcomplete 已经安装."
	else
		echo "argcomplete 未安装."
		echo "尝试安装argcomplete"
		pip3 install -r ./requirements.txt
		if pip list --verbose | grep -q "argcomplete"; then
			echo "argcomplete安装完成"
		else
			return 1
		fi
	fi
	# 注册 magic_eyes_cli
	if eval "$(register-python-argcomplete ./magic_eyes_cli)"; then
		echo "magic_eyes_cli注册成功"
	else
		echo "magic_eyes_cli注册失败"
		return 1
	fi
	return 0
}

# 调用函数并获取返回值
check_conditions
exit_status=$?
# 根据返回值输出最终结果
if [ $exit_status -eq 0 ]; then
    echo "OK"
else
    echo "条件不满足"
fi





