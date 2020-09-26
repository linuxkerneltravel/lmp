package controllers

import (
	"github.com/gin-gonic/gin"
	"lmp/logic"
	"lmp/models"
	"lmp/settings"
	"net/http"
)

func Collect(c *gin.Context) {
	m := fillConfigMessage(c)
	//fmt.Println(m)
	//fmt.Println(m.BpfFilePath)

	//执行逻辑
	logic.DoCollect(m)

	c.Redirect(http.StatusMovedPermanently, "http://"+settings.Conf.GrafanaConfig.IP)
	return
}

func fillConfigMessage(c *gin.Context) models.ConfigMessage {
	var m models.ConfigMessage

	if _, ok := c.GetPostForm("dispatchingdelay"); ok {
		m.DispatchingDelay = true
		m.BpfFilePath = append(m.BpfFilePath, settings.Conf.PluginConfig.Path+"dispatchingdelay.py")
	} else {
		m.DispatchingDelay = false
	}
	if _, ok := c.GetPostForm("waitingqueuelength"); ok {
		m.WaitingQueueLength = true
		m.BpfFilePath = append(m.BpfFilePath, settings.Conf.PluginConfig.Path+"waitingqueuelength.py")
	} else {
		m.WaitingQueueLength = false
	}
	if _, ok := c.GetPostForm("softirqtime"); ok {
		m.SoftIrqTime = true
		m.BpfFilePath = append(m.BpfFilePath, settings.Conf.PluginConfig.Path+"softirqtime.py")
	} else {
		m.SoftIrqTime = false
	}
	if _, ok := c.GetPostForm("hardirqtime"); ok {
		m.HardIrqTime = true
		m.BpfFilePath = append(m.BpfFilePath, settings.Conf.PluginConfig.Path+"hardirqtime.py")
	} else {
		m.HardIrqTime = false
	}
	if _, ok := c.GetPostForm("oncputime"); ok {
		m.OnCpuTime = true
		m.BpfFilePath = append(m.BpfFilePath, settings.Conf.PluginConfig.Path+"oncputime.py")
	} else {
		m.OnCpuTime = false
	}
	if _, ok := c.GetPostForm("vfsstat"); ok {
		m.Vfsstat = true
		m.BpfFilePath = append(m.BpfFilePath, settings.Conf.PluginConfig.Path+"vfsstat.py")
	} else {
		m.Vfsstat = false
	}
	if _, ok := c.GetPostForm("dcache"); ok {
		m.Vfsstat = true
		m.BpfFilePath = append(m.BpfFilePath, settings.Conf.PluginConfig.Path+"dcache.py")
	} else {
		m.Dcache = false
	}
	// Todo : Is this PID process exists?
	if _, ok := c.GetPostForm("pid"); ok {
		m.PidFlag = true
		// Then store the real pid number
		if pid, ok := c.GetPostForm("pidnum"); ok {
			if pid != "-1" {
				m.Pid = pid
			} else {
				m.PidFlag = false
			}
		} else {
			m.PidFlag = false
		}
	} else {
		m.PidFlag = false
	}

	return m
}
