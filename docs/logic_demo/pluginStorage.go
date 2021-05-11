package logic

import (
	"bufio"
	"errors"
	"io/ioutil"
	"os"
	"strings"
)

type PluginStorage struct {
	PgMp map[string]*Plugin
}

var PgStoarage = PluginStorage{
	PgMp: map[string]*Plugin{},
}

// 方便controller层获得当前所有的指标名
func (ps PluginStorage) GetAllPluginesKey() []string {
	keys := make([]string, 0, len(ps.PgMp))
	for k := range ps.PgMp {
		keys = append(keys, k)
	}
	return keys
}

// 获得某一个具体的插件
func (ps PluginStorage) GetPlugin(name string) (*Plugin, error) {
	p, exist := ps.PgMp[name]
	if exist {
		return p, nil
	}
	return nil, errors.New("no such plugin")
}

// 执行此次输入的所有的指标
func (ps *PluginStorage) RunAllPlugines(mp map[string]uint32) error {
	exitChan := make(chan bool, len(mp))

	for name, time := range mp {
		pg, err := ps.GetPlugin(name)
		if err != nil {
			exitChan <- true
			continue
		}

		go pg.Run(time, exitChan)
	}

	for i := 0; i < len(mp); i++ {
		<-exitChan
	}
	return nil
}

// map初始化，插件组织形式为一个插件一个文件夹，每个文件夹下都有一个doc.txt文件记录插件信息
func (ps *PluginStorage) Init(dirPath string) error {
	dir, err := ioutil.ReadDir(dirPath)
	if err != nil {
		return errors.New("no such path")
	}

	pthSep := string(os.PathSeparator)

	for _, fi := range dir {
		// 目录代表一个指标
		if fi.IsDir() {
			doc, err := os.Open(dirPath + pthSep + fi.Name() + pthSep + "doc.txt")
			if err != nil {
				continue
			}
			defer doc.Close()

			var pg Plugin
			buf := bufio.NewScanner(doc)
			for {
				if !buf.Scan() {
					break
				}
				line := buf.Text()
				line = strings.TrimSpace(line)
				strSlice := strings.Split(line, ";")

				pg.PgType = strTypeMap[strSlice[0]]
				pg.ExecPath = strSlice[1]
			}
			pg.PgState = PgStateSleeping
			pg.RunTime = 0

			ps.PgMp[fi.Name()] = &pg
		}
	}
	return nil
}
