package config

import (
	"collector/src/utils"
	_ "collector/src/utils"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
	"regexp"
)
type Sysfs struct {

	Option string
}

func NewSysfs() *Sysfs {
	return &Sysfs{
		Option: "/sys",
	}
}

func (this *Sysfs)Get(key string) string  {

	data,err :=ioutil.ReadFile(utils.Format("%s/%s",this.Option,key))
	if err != nil {
		log.Printf("Open file faild ! : %+v\n",err)
		return ""
	}
	pattern := regexp.MustCompile(".*\\[(.*)\\].*")
	searchObj := pattern.FindStringSubmatch(string(data))

	if searchObj != nil {
		return searchObj[1]
	}
	return string(data)
}
func (this *Sysfs)Set(key string,value interface{})   {
	var format string
	switch value.(type){
	case string:
		format = "%s"
		 break
	case int:
		format = "%d"
		 break
	default:
		log.Fatalf("Pramater is vaild! : %+v", value)
		return
	}
	fp,e := os.OpenFile(utils.Format("%s/%s",this.Option,key), os.O_RDWR|os.O_TRUNC, 0666)  //打开文件
	if e != nil {
		log.Fatalf("Open file error: %+v", e)
	}

	_, err := io.WriteString(fp, fmt.Sprintf(format, value))
	if err != nil {
		log.Fatalf("Set parm: %+v, error: %+v", value, err)
	}
}

