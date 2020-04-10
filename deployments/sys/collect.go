package sys

import (
	"fmt"
	"github.com/gin-gonic/gin"
	"lmp_ui/deployments/message"
	_ "lmp_ui/internal/BPF"
	_ "net/http"
)

type Data struct{}

func (d *Data)Collect(c *gin.Context) {
	//得到前端发来的配置信息
	m := fillConfigMessage(c)
	//将配置信息发送给BPF generator
	//var b BPF.BPFBody
	//file := b.Generator(&m)

	fmt.Println(m)

	//c.JSON(http.StatusOK,name)
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
