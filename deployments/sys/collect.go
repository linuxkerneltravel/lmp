package sys

import (
	"fmt"

	bpf "lmp/internal/BPF"
	"lmp/pkg/model"
)

type Data struct{}

func (d *Data) Handle(m *model.ConfigMessage) {
	//生成python文件和C文件
	d.Generator(m)
}

//根据配置，生成python文件和C文件
//TODO..接收配置信息
func (d *Data) Generator(m *model.ConfigMessage) {
	//先创建python文件
	py := bpf.NewConcreteBuilderPy()
	//把创建好的ConcreteBuilderPy传递给DirectorPy
	directorpy := bpf.NewDirectorPy(&py)
	//开始构造python文件
	directorpy.ConstructPy()
	result1 := py.GetResultPy()
	fmt.Println(result1)
	//TODO..

	//创建C文件
	C := bpf.NewConcreteBuilderC()
	//把创建好的ConcreteBuilderPy传递给DirectorPy
	directorc := bpf.NewDirectorC(&C)
	//开始构造python文件
	directorc.ConstructC()
	result2 := py.GetResultC()
	fmt.Println(result2)
	//TODO..
}
