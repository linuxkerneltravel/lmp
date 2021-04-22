package logic

func DoCollect(plugins *PluginStorage) (err error) {
	//todo:save all pids
	size := len(plugins.pluginStorage)
	exitChan := make(chan bool, size)

	if err = plugins.CollectData(exitChan); err != nil {
		return err
	}

	for i := 0; i < size; i++ {
		<-exitChan
	}

	return nil
}
