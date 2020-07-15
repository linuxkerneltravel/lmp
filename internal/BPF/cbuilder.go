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

//定义生成者模式中的Builder，这里的CBuilder是C文件生成的方法
type CBuilder interface {
	AddCommonCFileFront()
	AddPrivateCFile()
	AddCommonCFileEnd()
}

//具体来创建python文件的ConcreteBuilder

type ConcreteBuilderC struct {
	f *os.File
	m *model.ConfigMessage
}

//返回ConcreteBuilderC的实例
func NewConcreteBuilderC(m *model.ConfigMessage) ConcreteBuilderC {
	return ConcreteBuilderC{
		f: common.Creatfile(config.BpfPathC),
		m: m,
	}
}

//实现接口的方法
func (c *ConcreteBuilderC) AddCommonCFileFront() {

	common.CopyFileContext("./internal/bpfcode/bpf.txt", config.BpfPathC)

}
func (c *ConcreteBuilderC) AddPrivateCFile() {
	if c.m.Vfsstat {
		common.ReplceStringInFile(config.BpfPathC, "VFSSTAT-DATATYPE", bpfcode.Vfsstatdatatype)
	} else {
		common.ReplceStringInFile(config.BpfPathC, "VFSSTAT-DATATYPE", "")
	}
}
func (c *ConcreteBuilderC) AddCommonCFileEnd() {
	if c.m.Vfsstat {
		common.ReplceStringInFile(config.BpfPathC, "VFSSTAT-CODE", bpfcode.Vfsstatcode)
	} else {
		common.ReplceStringInFile(config.BpfPathC, "VFSSTAT-CODE", "")
	}
}

//最后生成的成果
type ProductC struct {
	f *os.File
}

//生成成果，
func (b *ConcreteBuilderC) GetResultC() ProductC {
	return ProductC{
		f: common.Getfile(config.BpfPathC),
	}
}
