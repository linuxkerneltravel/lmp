package sys

import (
	"fmt"
	"github.com/gin-gonic/gin"
	"lmp_ui/deployments/message"
	"lmp_ui/internal/BPF"
	_ "net/http"
)

type Data struct{}

func (d *Data)Handle(c *gin.Context) {
	//处理前端的配置消息
	d.Collect(c)
	//生成python文件和C文件
	d.Generator(c)
}

func (d *Data)Collect(c *gin.Context) {
	//得到前端发来的配置信息
	m := fillConfigMessage(c)
	//TODO..

	fmt.Println(m)

}

//根据配置，生成python文件和C文件
//TODO..接收配置信息
func (d *Data)Generator(c *gin.Context) {
	//先创建python文件
	py := bpf.NewConcreteBuilderPy()
	//把创建好的ConcreteBuilderPy传递给DirectorPy
	directorpy := bpf.NewDirectorPy(&py)
	//开始构造python文件
	directorpy.ConstructPy()
	result1 := py.GetResultPy()
	fmt.Println(result1)
	//TODO..

	//创建C文件
	C := bpf.NewConcreteBuilderC()
	//把创建好的ConcreteBuilderPy传递给DirectorPy
	directorc := bpf.NewDirectorC(&C)
	//开始构造python文件
	directorc.ConstructC()
	result2 := py.GetResultC()
	fmt.Println(result2)
	//TODO..
}


func fillConfigMessage(c *gin.Context) message.ConfigMessage {
	var m message.ConfigMessage
	if _,ok:= c.GetPostForm("dispatchingdelay"); ok {
		m.DispatchingDelay = true
	} else {
		m.DispatchingDelay = false
	}
	if _,ok:= c.GetPostForm("waitingqueuelength"); ok {
		m.WaitingQueueLength = true
	} else {
		m.WaitingQueueLength = false
	}
	if _,ok:= c.GetPostForm("softirqtime"); ok {
		m.SoftIrqTime = true
	} else {
		m.SoftIrqTime = false
	}
	if _,ok:= c.GetPostForm("hardirqtime"); ok {
		m.HardIrqTime = true
	} else {
		m.HardIrqTime = false
	}
	if _,ok:= c.GetPostForm("oncputime"); ok {
		m.OnCpuTime = true
	} else {
		m.OnCpuTime = false
	}
	return m
}
