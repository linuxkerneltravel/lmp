package controllers

import (
	_ "context"
	"fmt"
	_ "time"

	"lmp/logic"
	"lmp/models"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

func Collect(c *gin.Context) {
	// 1、填充表单数据，得到所有的参数
	//m := fillFrontMessage(c)
	//fmt.Println("I am here", m)

	p := new(models.ConfigMessage)
	if err := c.ShouldBindJSON(p); err != nil {
		zap.L().Error("Login with invalid param", zap.Error(err))
		ResponseError(c, CodeInvalidParam)
		return
	}

	fmt.Println("controller p is here", p)
	// 2、得到当前的用户名，之后利用这个用户名作为influxdb的dbname
	dbname, err := getCurrentUsername(c)
	if err != nil {
		zap.L().Error("error in getCurrentUsername()", zap.Error(err))
	}
	// 3、把dbname作为一个参数和填充好的表单数据一块下发给logic层
	if err := logic.DoCollect(*p, dbname); err != nil {
		zap.L().Error("error in logic.DoCollect()", zap.Error(err))
	}
	//ResponseRediect(c, settings.Conf.GrafanaConfig.IP)

	ResponseSuccess(c, fmt.Sprintf("collecting..."))
}

//func fillFrontMessage(c *gin.Context) models.ConfigMessage {
//	var m models.ConfigMessage
//
//	if v, ok := c.GetPostForm("cpuutilize"); ok && v == "true" {
//		m.Cpuutilize = true
//		m.BpfFilePath = append(m.BpfFilePath, settings.Conf.PluginConfig.Path+"cpuutilize.py")
//	} else {
//		m.Cpuutilize = false
//	}
//	if v, ok := c.GetPostForm("irq"); ok && v == "true" {
//		m.Irq = true
//		m.BpfFilePath = append(m.BpfFilePath, settings.Conf.PluginConfig.Path+"irq.py")
//	} else {
//		m.Irq = false
//	}
//	if v, ok := c.GetPostForm("picknext"); ok && v == "true" {
//		m.Picknext = true
//		m.BpfFilePath = append(m.BpfFilePath, settings.Conf.PluginConfig.Path+"picknext.py")
//	} else {
//		m.Picknext = false
//	}
//	if v, ok := c.GetPostForm("taskswitch"); ok && v == "true" {
//		m.Taskswitch = true
//		m.BpfFilePath = append(m.BpfFilePath, settings.Conf.PluginConfig.Path+"taskswitch.py")
//	} else {
//		m.Taskswitch = false
//	}
//	if v, ok := c.GetPostForm("harddiskreadwritetime"); ok && v == "true" {
//		m.Harddiskreadwritetime = true
//		m.BpfFilePath = append(m.BpfFilePath, settings.Conf.PluginConfig.Path+"harddiskreadwritetime.py")
//	} else {
//		m.Harddiskreadwritetime = false
//	}
//	if v, ok := c.GetPostForm("memusage"); ok && v == "true" {
//		m.Memusage = true
//		m.BpfFilePath = append(m.BpfFilePath, settings.Conf.PluginConfig.Path+"memusage.py")
//	} else {
//		m.Memusage = false
//	}
//	if v, ok := c.GetPostForm("netlatency"); ok && v == "true" {
//		m.Netlatency = true
//		//m.BpfFilePath = append(m.BpfFilePath, settings.Conf.PluginConfig.Path+"netlatency.py")
//	} else {
//		m.Netlatency = false
//	}
//
//	// fill timeField
//	if collectTime, ok := c.GetPostForm("collecttime"); ok {
//		// 记得转为秒
//		tmpTime, _ := strconv.Atoi(collectTime)
//		m.CollectTime = tmpTime * 60
//	} else {
//		m.CollectTime = settings.Conf.PluginConfig.CollectTime * 60
//	}
//
//	return m
//}
