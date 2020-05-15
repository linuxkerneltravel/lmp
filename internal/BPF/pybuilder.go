package bpf

import (
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
		f:   os.File{},	//TODO..
		m: m,
	}
}

//实现接口的方法
func (c *ConcreteBuilderPy)AddCommonPyFileFront() {
	//TODO..
}
func (c *ConcreteBuilderPy)AddPrivatePyFile() {
	//TODO..
}
func (c *ConcreteBuilderPy)AddCommonPyFileEnd() {
	//TODO..
}

//最后生成的成果
type ProductPy struct {
	f os.File
	status bool
}

//生成成果，
func (b *ConcreteBuilderPy)GetResultPy() ProductPy {
	return ProductPy{
		f:      b.f,
		status: true,
	}
}



