package models

type PluginMessage struct {
	Plugins     map[string]string `json:"plugins"`
	CollectTime int               `json:"pluginsruntime"`
}
