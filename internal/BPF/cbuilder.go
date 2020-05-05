package bpf

import (
	"lmp/config"
	"lmp/deployments/common"
	"lmp/internal/bpfcode"
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
}

//返回ConcreteBuilderC的实例
func NewConcreteBuilderC() ConcreteBuilderC {
	return ConcreteBuilderC{
		f: common.Creatfile(config.BpfPath),
	}
}

//实现接口的方法
func (c *ConcreteBuilderC) AddCommonCFileFront() {

	common.CopyFileContext("./internal/bpfcode/bpf.txt", config.BpfPath)

}
func (c *ConcreteBuilderC) AddPrivateCFile() {

	common.ReplceStringInFile(config.BpfPath, "VFSSTAT-DATATYPE", bpfcode.Vfsstatdatatype)

}
func (c *ConcreteBuilderC) AddCommonCFileEnd() {

	common.ReplceStringInFile(config.BpfPath, "VFSSTAT-CODE", bpfcode.Vfsstatcode)
}

//最后生成的成果
type ProductC struct {
	f *os.File
}

//生成成果，
func (b *ConcreteBuilderC) GetResultC() ProductC {
	return ProductC{
		f: common.Getfile(),
	}
}
