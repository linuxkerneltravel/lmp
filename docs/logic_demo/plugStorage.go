package logic

import (
	"errors"
	"io/ioutil"
	"os"
	"strings"
	"time"
)

type PluginStorage struct {
	Mp map[string]Plugin
}

var PlugStr = PluginStorage{
	Mp: map[string]Plugin{},
}

func (ps PluginStorage) getPlugin(name string) (Plugin, error) {
	p, exist := ps.Mp[name]
	if exist {
		return p, nil
	}
	return nil, errors.New("no Such Plugin")
}

func (ps *PluginStorage) RunPlugines(mp map[string]uint32) {
	var maxTime uint32 = 0
	for name, time := range mp {
		plug, err := ps.getPlugin(name)
		if err != nil {
			continue
		}
		if time > maxTime {
			maxTime = time
		}
		go plug.Run(time)
	}
	timeTicker := time.NewTicker(time.Minute * time.Duration(maxTime))
	<-timeTicker.C
	timeTicker.Stop()
}

func (ps *PluginStorage) Init(dirPath string) error {
	dir, err := ioutil.ReadDir(dirPath)
	if err != nil {
		return errors.New("no such Path")
	}

	pthSep := string(os.PathSeparator)

	for _, fi := range dir {
		if fi.IsDir() { // for C 

		} else {
			py := strings.HasSuffix(fi.Name(), ".py")
			sh := strings.HasSuffix(fi.Name(), ".sh")

			if py {
				name := fi.Name()
				name = name[:len(name)-4]

				var bccplugin = &BccPlugin{
					PluginInfo: PluginInfo{
						PluginState: PluginSleeping,
						ExecPath: dirPath + pthSep + fi.Name(),
						RunTime: 0,
					},
				}

				ps.Mp[name] = bccplugin
			} else if sh {
				name := fi.Name()
				name = name[:len(name)-4]

				var shellplugin = &ShellPlugin{
					PluginInfo: PluginInfo{
						PluginState: PluginSleeping,
						ExecPath: dirPath + pthSep + fi.Name(),
						RunTime: 0,
					},
				}

				ps.Mp[name] = shellplugin
			}
		}
	}
	return nil
}
