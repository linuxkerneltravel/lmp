package logic

import (
	"github.com/linuxkerneltravel/lmp/models"

	"go.uber.org/zap"
)

func DoCollect(frontPlugins *models.PluginMessage) (err error) {
	//todo:save all pids

	plugins, err := CreatePluginStorage(frontPlugins)
	if err != nil {
		zap.L().Error("error in plugins.CreatePluginStorage(frontPlugins)", zap.Error(err))
		return err
	}

	if err = plugins.CollectData(); err != nil {
		return err
	}

	return nil
}
