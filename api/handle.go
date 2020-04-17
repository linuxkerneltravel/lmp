package api

import (
	"fmt"
	"lmp/deployments/sys"
	"lmp/pkg/model"

	"github.com/gin-gonic/gin"
)

func init() {
	SetRouterRegister(func(router *RouterGroup) {
		engine := router.Group("/api")

		engine.GET("/ping", Ping)
		engine.POST("/data/collect", do_collect)
	})
}

func do_collect(c *Context) {
	data := sys.Data{}
	m := fillConfigMessage(c)
	//TODO..

	fmt.Println(m)
	data.Handle(&m)
	c.JSON(200, gin.H{"message": "do_collect"})
}

func Ping(c *Context) {
	c.JSON(200, gin.H{"message": "pong"})
}

func fillConfigMessage(c *Context) model.ConfigMessage {
	var m model.ConfigMessage
	if _, ok := c.GetPostForm("dispatchingdelay"); ok {
		m.DispatchingDelay = true
	} else {
		m.DispatchingDelay = false
	}
	if _, ok := c.GetPostForm("waitingqueuelength"); ok {
		m.WaitingQueueLength = true
	} else {
		m.WaitingQueueLength = false
	}
	if _, ok := c.GetPostForm("softirqtime"); ok {
		m.SoftIrqTime = true
	} else {
		m.SoftIrqTime = false
	}
	if _, ok := c.GetPostForm("hardirqtime"); ok {
		m.HardIrqTime = true
	} else {
		m.HardIrqTime = false
	}
	if _, ok := c.GetPostForm("oncputime"); ok {
		m.OnCpuTime = true
	} else {
		m.OnCpuTime = false
	}
	return m
}
