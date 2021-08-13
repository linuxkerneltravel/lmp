package logic

import (
	"github.com/linuxkerneltravel/lmp/dao/influxdb"
	"github.com/linuxkerneltravel/lmp/logger"
	"github.com/linuxkerneltravel/lmp/models"

	client "github.com/influxdata/influxdb1-client/v2"
)

func DoCollect(frontPlugins *models.PluginMessage) (err error) {
	//todo:save all pids

	plugins, err := CreatePluginStorage(frontPlugins)
	if err != nil {
		logger.Error("error in plugins.CreatePluginStorage(frontPlugins)", err)
		return err
	}

	if err = plugins.CollectData(); err != nil {
		return err
	}

	return nil
}

func DoQueryIRQ() (res []client.Result, err error) {
	// 调用dao层influxdb API
	res, err = influxdb.QueryDB(`select last("duration") from "irq"`)
	if err != nil {
		logger.Error("ERROR in DoQueryIRQ():", err)
		return nil, err
	}
	return
}

func DoQueryCpuUtilize() (res []client.Result, err error) {
	res, err = influxdb.QueryDB(`select last("perce") from "cpuutilize"`)
	if err != nil {
		logger.Error("ERROR in DoQueryIRQ():", err)
		return nil, err
	}
	return
}

func DoQueryPickNext() (res []client.Result, err error) {
	res, err = influxdb.QueryDB(`select last("duration") from "picknext"`)
	if err != nil {
		logger.Error("ERROR in DoQueryPickNext():", err)
		return nil, err
	}
	return
}

func DoQueryTaskSwitch() (res []client.Result, err error) {
	res, err = influxdb.QueryDB(`select last("duration") from "taskswitch"`)
	if err != nil {
		logger.Error("ERROR in DoQueryTaskSwitch():", err)
		return nil, err
	}
	return
}

func DoQueryHardDiskReadWriteTime() (res []client.Result, err error) {
	res, err = influxdb.QueryDB(`select last("lat") from "HardDiskReadWriteTime"`)
	if err != nil {
		logger.Error("ERROR in DoQueryHardDiskReadWriteTime():", err)
		return nil, err
	}
	return
}

func DoQueryWaterMark() (res []client.Result, err error) {
	res, err = influxdb.QueryDB(`select last("normal") from "memusage"`)
	if err != nil {
		logger.Error("ERROR in DoQueryWaterMark():", err)
		return nil, err
	}
	return
}
