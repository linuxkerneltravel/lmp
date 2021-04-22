package logic

import "github.com/linuxkerneltravel/lmp/models"

type PluginStorage struct {
	pluginStorage map[string]Plugin
}

func (p *PluginStorage) CreatePluginStorage(message *models.PluginMessage) (*PluginStorage, error) {
	return &PluginStorage{}, nil
}

func (p *PluginStorage) CollectData(exitChan chan bool) error {
	return nil
}
