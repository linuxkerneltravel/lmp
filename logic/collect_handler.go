package logic

import (
	"github.com/linuxkerneltravel/lmp/models"

	"go.uber.org/zap"
)

func DoCollect(frontPlugins *models.PluginMessage) (err error) {
	//todo:save all pids
	size := len(frontPlugins.Plugins)
	exitChan := make(chan bool, size)

	plugins := new(PluginStorage)
	plugins, err = plugins.CreatePluginStorage(frontPlugins)
	if err != nil {
		zap.L().Error("error in plugins.CreatePluginStorage(frontPlugins)", zap.Error(err))
		return err
	}

	if err = plugins.CollectData(exitChan); err != nil {
		return err
	}

	for i := 0; i < size; i++ {
		<-exitChan
	}

	return nil
}
