package logic

type PluginStorage struct {
	pluginStorage map[string]Plugin
}

func (p *PluginStorage) CreatePluginStorage() PluginStorage {
	return PluginStorage{}
}

func (p *PluginStorage) CollectData() {

}
