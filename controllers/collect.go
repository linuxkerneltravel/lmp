package controllers

import (
	_ "context"
	"fmt"
	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
	"lmp/logic"
	"lmp/models"
	"lmp/settings"
	"strconv"
	_ "time"
)

func Collect(c *gin.Context) {
	// 1、填充表单数据，得到所有的参数
	m := fillFrontMessage(c)
	fmt.Println(m)

	// 2、得到当前的用户名，之后利用这个用户名作为influxdb的dbname
	dbname, err := getCurrentUsername(c)
	if err != nil {
		zap.L().Error("error in getCurrentUsername()", zap.Error(err))
	}

	// 3、把dbname作为一个参数和填充好的表单数据一块下发给logic层
	//ctx, cancel := context.WithTimeout(context.Background(), (time.Duration(m.CollectTime))*time.Second)
	//defer cancel()
	if err := logic.DoCollect(m, dbname); err != nil {
		zap.L().Error("error in logic.DoCollect()", zap.Error(err))
	}

	//ResponseRediect(c, settings.Conf.GrafanaConfig.IP)

	ResponseSuccess(c, fmt.Sprintf("collecting..."))
}

func fillFrontMessage(c *gin.Context) models.ConfigMessage {
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

	// fill timeField
	if collectTime, ok := c.GetPostForm("collecttime"); ok {
		// 记得转为秒
		tmpTime, _ := strconv.Atoi(collectTime)
		m.CollectTime = tmpTime * 60
	} else {
		m.CollectTime = settings.Conf.PluginConfig.CollectTime * 60
	}

	return m
}
