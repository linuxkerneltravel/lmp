package logic

import (
	"errors"
	"github.com/linuxkerneltravel/lmp/models"
)

type PluginMap map[string]Plugin

const (
	BCCPLUGIN  string = "bcc"
	CBPFPLUGIN string = "cbpf"
)

type PluginStorage struct {
	PluginMap   PluginMap
	CollectTime int
}

func CreatePluginStorage(frontPlugins *models.PluginMessage) (pluginStorage *PluginStorage, err error) {
	pluginStorage = new(PluginStorage)
	pluginStorage.PluginMap = make(PluginMap)
	pluginStorage.CollectTime = frontPlugins.CollectTime

	for pluginName, pluginType := range frontPlugins.Plugins {
		switch typeOfPlugin(pluginType) {
		case BCCPLUGIN:
			var bccPluginFactory BccPluginFactory
			pluginStorage.PluginMap[pluginName], err = bccPluginFactory.CreatePlugin(pluginName, pluginType)
			if err != nil {
				return nil, ErrorGetPluginFailed
			}
		case CBPFPLUGIN:
			var cbpfPluginFactory CbpfPluginFactory
			pluginStorage.PluginMap[pluginName], err = cbpfPluginFactory.CreatePlugin(pluginName, pluginType)
			if err != nil {
				return nil, ErrorGetPluginFailed
			}
		default:
			err = errors.New("Not a plugin!")
		}
	}

	return
}

func typeOfPlugin(pluginType string) string {
	return BCCPLUGIN
}

func (p *PluginStorage) CollectData() error {
	size := len(p.PluginMap)
	exitChan := make(chan bool, size)

	for _, plugin := range p.PluginMap {
		plugin.Run(exitChan, p.CollectTime)
	}

	for i := 0; i < size; i++ {
		<-exitChan
	}

	return nil
}
