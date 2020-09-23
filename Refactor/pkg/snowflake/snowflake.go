package snowflake

import (
	sf "github.com/bwmarrin/snowflake"
	"time"
)

// 在一台机器上启动服务之后，就启动了一个node
var node *sf.Node

// startTime：起始时间，例如2020-07-01
// machineID：这个分布式场景下，每个机器唯一的标识
func Init(startTime string, machineID int64) (err error) {
	// 搞一个时间因子，就从这个时间开始
	var st time.Time
	st, err = time.Parse("2006-01-02", startTime)
	if err != nil {
		return
	}
	// 初始化开始的时间
	sf.Epoch = st.UnixNano() / 1000000
	// 指定机器的ID
	node, err = sf.NewNode(machineID)
	return
}

// 需要产生ID的时候，调用这个函数：
func GenID() int64 {
	return node.Generate().Int64()
}

/*

单独测试下使用

func main() {
	// 我们在这里固定把机器编号写成1，当业务量大了以后，可以生成机器ID，起一个节点调用一下生成机器ID的方法就可以了
	// 所以在这里是当成是模块来用，而不是分布式了
	if err := Init("2020-07-01", 1); err != nil {
		fmt.Println("init failed, err:%v\n", err)
		return
	}
	id := GenID()
	fmt.Println(id)
}
*/
