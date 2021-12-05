#!/bin/bash
echo "--------------------------begin install--------------------------"

echo -e "安装前请确保已经有以下环境:\n1. bcc环境\n2. golang：go1.12 ~ go1.15\n"


while true
do
    echo -n "请确认您的选择是或否。 （Y(y)表示是，N(n)表示否）： "
    echo ' '
    read CONFIRM
    case $CONFIRM in
        y|Y) break ;;
        n|N)
        echo "你选择了 : " $CONFIRM
    exit
;;
*) echo "请只输入 Y(y)/N(n)"
esac
done

path=`pwd`
 
function docker_install()
{
	echo "====检查Docker......"
	docker -v
    if [ $? -eq  0 ]; then
        echo "====检查到Docker已安装!"
    else
    	echo "====安装docker环境..."
        curl -sSL https://get.daocloud.io/docker | sh
        echo "安装docker环境...安装完成!"
    fi
    echo "====启动docker===="
    systemctl restart docker.service
    echo "====docker启动完成===="
    systemctl enable docker
    echo "====设置docker 开机启动===="
    # 创建公用网络==bridge模式
    #docker network create share_network
}


function mysql_install()
{
        echo "====检查 Mysql......"
        mysql --version
    if [ $? -eq  0 ]; then
        echo "====检查到Mysql已安装!"
    else
        echo "====安装Mysql 环境..."
	apt-get install mysql-server
        echo "====安装Mysql...安装完成!"
    fi
    echo "====启动Mysql===="
    systemctl restart mysql.service
    echo "====Mysql启动完成===="
}



function docker_pull_images()
{
    # 获取已经有的所有镜像
    existImages=`docker images |awk '{print $1":"$2}'` # 获取当前所有镜像
    echo ====当前已经安装镜像:$existImages
    if [[ $existImages =~ grafana/grafana ]]
    then
        echo "====grafana/grafana 已经安装"
    else
        echo "====grafana/grafana 没有安装"
        echo "====开始安装 grafana/grafana"
        docker pull grafana/grafana
    fi

    if [[ $existImages =~ influxdb:1.8.3 ]]
    then
        echo "====influxdb 已经安装"
    else
        echo "====influxdb 没有安装"
        echo "====开始安装 influxdb"
        docker pull influxdb:1.8.3
    fi

}

function docker_start()
{
	#start grafana
	docker run -d -p 3000:3000 --name=grafana grafana/grafana
	#start influxdb
	docker run -d \
    	-p 8083:8083 \
    	-p 8086:8086 \
    	--name influxdb \
    	-v $path/test/influxdb_config/default.conf:/etc/influxdb/influxdb.conf \
    	-v $path/test/influxdb_config/data:/var/lib/influxdb/data \
    	-v $path/test/influxdb_config/meta:/var/lib/influxdb/meta influxdb:1.8.3
	
}


function test()
{
if ls; then 
	echo notify user OK >&2
else        
	echo notify user FAIL >&2
	return -1
fi

}
#### 执行函数
docker_install
mysql_install
docker_pull_images
docker_start
echo "===================="
echo "==首次直接回车即可=="
echo "===================="
make mysqlpasswdinit
echo "========================"
echo "==当前密码默认为123456=="
echo "========================"
make db

make


#echo export PATH=$PATH:$path >>/etc/profile
#source /etc/profile
echo "====环境配置完毕,请输入./lmp 开始运行"
