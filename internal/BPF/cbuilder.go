package bpf

import "os"

//定义生成者模式中的Builder，这里的CBuilder是C文件生成的方法
type CBuilder interface {
	AddCommonCFileFront()
	AddPrivateCFile()
	AddCommonCFileEnd()
}

//具体来创建python文件的ConcreteBuilder
type ConcreteBuilderC struct {
	f os.File
	status bool
}

//返回ConcreteBuilderPy的实例
func NewConcreteBuilderC() ConcreteBuilderC {
	return ConcreteBuilderC{
		f:   os.File{},	//TODO..
		status: false,
	}
}

//实现接口的方法
func (c *ConcreteBuilderC)AddCommonCFileFront() {
	//TODO..
}
func (c *ConcreteBuilderC)AddPrivateCFile() {
	//TODO..
}
func (c *ConcreteBuilderC)AddCommonCFileEnd() {
	//TODO..
}

//最后生成的成果
type ProductC struct {
	f os.File
	status bool
}

//生成成果，
func (b *ConcreteBuilderPy)GetResultC() ProductC {
	return ProductC{
		f:      b.f,
		status: true,
	}
}



