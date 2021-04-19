package logic

type PluginStorage struct {
	pluginStorage map[string]Plugin
}

func (p * PluginStorage)Init() {

}

type AllPluginStorage struct {
	* PluginStorage
}

func (p * AllPluginStorage)Watch() {

}

func (p * AllPluginStorage) Update() {

}

type TaskPluginStorage struct {
	* PluginStorage
}

func (p * TaskPluginStorage)CollectData() {

}
