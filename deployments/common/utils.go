//
// Created by Qiangzhixing Cheng
//
package common

import (
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"strings"
)

//生成初始文件返回文件指针
func Creatfile(path string) *os.File {
	file, err := os.Create(path)
	if err != nil {
		fmt.Println("created failed")
	}
	defer file.Close()
	return file
}

//打开文件返回文件指针
func Getfile(location string) *os.File {
	file, err := os.Open(location)
	if err != nil {
		fmt.Println("return file failed")
	}
	defer file.Close()
	return file
}

//把filepath文件中的oldstring用newstring替换
func ReplceStringInFile(filpath string, oldstring string, newstring string) {
	oldContext, err := ioutil.ReadFile(filpath)
	if err != nil {
		fmt.Println("read filecontext failed")
	}
	newContext := strings.Replace(string(oldContext), oldstring, newstring, 1)
	err = ioutil.WriteFile(filpath, []byte(newContext), 0644)
	if err != nil {
		fmt.Println("write filecontext failed")
	}

}

//把outfile中的内容复制给infile文件
func CopyFileContext(outfile, infile string) {

	f1, err1 := os.Open(outfile)
	if err1 != nil {
		fmt.Println("open outfile failed")
	}
	f2, err2 := os.OpenFile(infile, os.O_WRONLY|os.O_CREATE, os.ModePerm)
	if err2 != nil {
		fmt.Println("copy to infile failed")
	}
	defer f1.Close()
	defer f2.Close()
	io.Copy(f2, f1)

}
