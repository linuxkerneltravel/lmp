package controllers

import (
	_ "context"
	"fmt"
	"strconv"
	_ "time"

	"lmp/logic"
	"lmp/models"
	"lmp/settings"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

func Collect(c *gin.Context) {
	m := fillFrontMessage(c)

	if err := logic.DoCollect(m); err != nil {
		zap.L().Error("error in logic.DoCollect()", zap.Error(err))
		ResponseError(c, CodeInvalidParam)
		return
	}

	ResponseSuccess(c, fmt.Sprintf("collecting..."))
}

func fillFrontMessage(c *gin.Context) models.ConfigMessage {
	var m models.ConfigMessage

	if v, ok := c.GetPostForm("cpuutilize"); ok && v == "true" {
		m.Cpuutilize = true
		m.BpfFilePath = append(m.BpfFilePath, settings.Conf.PluginConfig.Path+"cpuutilize.py")
	} else {
		m.Cpuutilize = false
	}
	if v, ok := c.GetPostForm("irq"); ok && v == "true" {
		m.Irq = true
		m.BpfFilePath = append(m.BpfFilePath, settings.Conf.PluginConfig.Path+"irq.py")
	} else {
		m.Irq = false
	}
	if v, ok := c.GetPostForm("memusage"); ok && v == "true" {
		m.Memusage = true
		m.BpfFilePath = append(m.BpfFilePath, settings.Conf.PluginConfig.Path+"memusage.py")
	} else {
		m.Memusage = false
	}
	if v, ok := c.GetPostForm("picknexttask"); ok && v == "true" {
		m.Picknexttask = true
		m.BpfFilePath = append(m.BpfFilePath, settings.Conf.PluginConfig.Path+"picknext.py")
	} else {
		m.Picknexttask = false
	}
	if v, ok := c.GetPostForm("runqlen"); ok && v == "true" {
		m.Runqlen = true
		m.BpfFilePath = append(m.BpfFilePath, settings.Conf.PluginConfig.Path+"waitingqueuelength.py")
	} else {
		m.Runqlen = false
	}
	if v, ok := c.GetPostForm("vfsstat"); ok && v == "true" {
		m.Vfsstat = true
		m.BpfFilePath = append(m.BpfFilePath, settings.Conf.PluginConfig.Path+"vfsstat.py")
	} else {
		m.Vfsstat = false
	}
	if v, ok := c.GetPostForm("dcache"); ok && v == "true" {
		m.Dcache = true
		m.BpfFilePath = append(m.BpfFilePath, settings.Conf.PluginConfig.Path+"dcache.py")
	} else {
		m.Dcache = false
	}

	if collectTime, ok := c.GetPostForm("collecttime"); ok {
		tmpTime, _ := strconv.Atoi(collectTime)
		m.CollectTime = tmpTime * 60
	} else {
		m.CollectTime = settings.Conf.PluginConfig.CollectTime * 60
	}

	return m
}
