//
// Created by ChenYuZhao on 2020/7/1.
//
package bpf

import "os"

//定义全局切片，用于存放所有的插件
var pluginServices []*PluginService

type PluginService struct {
	F *os.File
	Name string
	Info string
}

func (p *PluginService) RegisterPluginService(name string, f *os.File, info string) {
	pluginServices = append(pluginServices, &PluginService{
		F : f,
		Name : name,
		Info : info,
	})
}

func (p *PluginService) SetInfo {

}

func (p *PluginService) Save2Mysql {

}

//


/*
type DirectorPy struct {
	//生成python文件的接口
	pyBuilder PyBuilder
}

type DirectorC struct {
	//生成C文件的接口
	cBuilder CBuilder
}

func NewDirectorPy(b PyBuilder) DirectorPy {
	return DirectorPy{
		pyBuilder: b,
	}
}

func NewDirectorC(c CBuilder) DirectorC {
	return DirectorC{
		cBuilder: c,
	}
}

//生成python文件的步骤，接口和实现分离
func (d *DirectorPy) ConstructPy() {
	d.pyBuilder.AddCommonPyFileFront()
	d.pyBuilder.AddPrivatePyFile()
	d.pyBuilder.AddCommonPyFileEnd()
}

//生成C文件的步骤，接口和实现分离
func (d *DirectorC) ConstructC() {
	d.cBuilder.AddCommonCFileFront()
	d.cBuilder.AddPrivateCFile()
	d.cBuilder.AddCommonCFileEnd()
}
*/