package bpf

import (
	"fmt"
	"io"
	"io/ioutil"
	"lmp/config"
	"lmp/internal/bpfcode"
	"os"
	"strings"
)

//定义生成者模式中的Builder，这里的CBuilder是C文件生成的方法
type CBuilder interface {
	AddCommonCFileFront()
	AddPrivateCFile()
	AddCommonCFileEnd()
}

//具体来创建python文件的ConcreteBuilder
/*
type ConcreteBuilderC struct {
	f os.File
	status bool
}
*/

type ConcreteBuilderC struct {
	f *os.File
	//	status bool
}

//返回ConcreteBuilderC的实例
func NewConcreteBuilderC() ConcreteBuilderC {
	return ConcreteBuilderC{
		f: CreatCfile(config.DefaultCollectorPath),
		//		status: false,
	}
}

//实现接口的方法
func (c *ConcreteBuilderC) AddCommonCFileFront() {
	//把bpfcode下面的bpf.c中的内容复制给path文件
	f1, err1 := os.Open("./internal/bpfcode/bpf.txt")
	if err1 != nil {
		fmt.Println("bpf.c open failed")
	}
	f2, err2 := os.OpenFile(config.DefaultCollectorPath, os.O_WRONLY|os.O_CREATE, os.ModePerm)
	if err2 != nil {
		fmt.Println("copy to initCfile failed")
	}
	defer f1.Close()
	defer f2.Close()
	io.Copy(f2, f1)

}
func (c *ConcreteBuilderC) AddPrivateCFile() {
	//进行替换bpf.c中的VFSSTAT-DATATYPE字符串
	oldContext, err := ioutil.ReadFile(config.DefaultCollectorPath)
	if err != nil {
		fmt.Println("read initCfile failed")
	}
	newContext := strings.Replace(string(oldContext), "VFSSTAT-DATATYPE", bpfcode.Vfsstatdatatype, 1)
	err = ioutil.WriteFile(config.DefaultCollectorPath, []byte(newContext), 0644)
	if err != nil {
		fmt.Println("write firstsstepcontext failed")
	}

}
func (c *ConcreteBuilderC) AddCommonCFileEnd() {
	oldContext, err := ioutil.ReadFile(config.DefaultCollectorPath)
	if err != nil {
		fmt.Println("read fistStepCfile failed")
	}
	newContext := strings.Replace(string(oldContext), "VFSSTAT-CODE", bpfcode.Vfsstatcode, 1)
	err = ioutil.WriteFile(config.DefaultCollectorPath, []byte(newContext), 0644)
	if err != nil {
		fmt.Println("write finalfile failed")
	}

}

//最后生成的成果
type ProductC struct {
	f *os.File
	//	status bool
}

//生成成果，
func (b *ConcreteBuilderC) GetResultC() ProductC {
	return ProductC{
		f: GetCfile(),
		//		status: true,
	}
}

//生成初始c文件返回文件指针
func CreatCfile(path string) *os.File {
	file, err := os.Create(config.DefaultCollectorPath)
	if err != nil {
		fmt.Println("created failed")
	}
	defer file.Close()
	return file
}

func GetCfile() *os.File {
	file, err := os.Open(config.DefaultCollectorPath)
	if err != nil {
		fmt.Println("return file failed")
	}
	defer file.Close()
	return file
}
