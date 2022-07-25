package main

import (
	"fmt"
	"gorm.io/driver/mysql"
	"gorm.io/gorm"
	"lmp/server/model/ebpfplugins"
	ebpfplugins2 "lmp/server/service/ebpfplugins"
	"log"
)

/*func main() {
	if err := ebpfplugins2.RunSinglePlugin("./helloword.py"); err != nil {
		fmt.Println(err)
	}
}*/
/*func main() {
	var test = ebpfplugins2.EbpfpluginsService{}
	var id = request.PluginInfo{69}
	test.LoadEbpfPlugins(id)
}*/
func main() {
	dsn := "root:123456@tcp(127.0.0.1:3306)/gva?charset=utf8mb4&parseTime=True&loc=Local"
	db, _ := gorm.Open(mysql.Open(dsn), &gorm.Config{})
	var plugin ebpfplugins.EbpfPlugins
	db.Where("id=?", 69).First(&plugin)
	fmt.Println(plugin)
	if err := ebpfplugins2.RunSinglePlugin(plugin.PluginPath); err != nil {
		log.Println(err)
	}
}
