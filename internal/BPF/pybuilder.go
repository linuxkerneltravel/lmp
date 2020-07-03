//
// Created by ChenYuZhao
// Modified by Qiangzhixing Cheng
//
package bpf

import (
	"lmp/config"
	"lmp/deployments/common"
	"lmp/internal/bpfcode"
	"lmp/pkg/model"
	"os"
)

// 定义生成者模式中的Builder，这里的Builder是python文件生成的方法
type PyBuilder interface {
	AddCommonPyFileFront()
	AddPrivatePyFile()
	AddCommonPyFileEnd()
}

//具体来创建python文件的ConcreteBuilder
type ConcreteBuilderPy struct {
	f *os.File
	m *model.ConfigMessage
}

//返回ConcreteBuilderPy的实例
func NewConcreteBuilderPy(m *model.ConfigMessage) ConcreteBuilderPy {
	return ConcreteBuilderPy{
		f: common.Creatfile(config.BpfPathPy), //TODO..
		m: m,
	}
}

//实现接口的方法
func (c *ConcreteBuilderPy) AddCommonPyFileFront() {
	common.CopyFileContext("./internal/bpfcode/bpf-py.txt", config.BpfPathPy)
}
func (c *ConcreteBuilderPy) AddPrivatePyFile() {
	if c.m.Vfsstat {
		common.ReplceStringInFile(config.BpfPathPy, "TIMESTAMP", bpfcode.TIMESTAMP)
		common.ReplceStringInFile(config.BpfPathPy, "ATTACHKPROBE", bpfcode.ATTACHKPROBE)
		common.ReplceStringInFile(config.BpfPathPy, "VFSSTATTYPES", bpfcode.VFSSTATTYPES)
		common.ReplceStringInFile(config.BpfPathPy, "VFSSTATCODE", bpfcode.VFSSTATCODE)

	} else {
		common.ReplceStringInFile(config.BpfPathPy, "TIMESTAMP", "")
		common.ReplceStringInFile(config.BpfPathPy, "ATTACHKPROBE", "")
		common.ReplceStringInFile(config.BpfPathPy, "VFSSTATTYPES", "")
		common.ReplceStringInFile(config.BpfPathPy, "VFSSTATCODE", "")

	}
}

func (c *ConcreteBuilderPy) AddCommonPyFileEnd() {
	//TODO..
}

//最后生成的成果
type ProductPy struct {
	f *os.File
	//status bool
}

//生成成果，
func (b *ConcreteBuilderPy) GetResultPy() ProductPy {
	return ProductPy{
		f: common.Getfile(config.BpfPathPy),
		//status: true,
	}
}
