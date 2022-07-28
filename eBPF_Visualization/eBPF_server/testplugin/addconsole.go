package main

import (
	request2 "lmp/server/model/common/request"
	"lmp/server/model/system/request"
	ebpfplugins2 "lmp/server/service/ebpfplugins"
	"lmp/server/service/system"
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
func initDb() {
	var initDBservice *system.InitDBService
	var initdb = request.InitDB{
		DBType:   "mysql",
		Host:     "127.0.0.1",
		Port:     "3306",
		UserName: "root",
		Password: "123456",
		DBName:   "gva",
	}
	if err := initDBservice.InitDB(initdb); err != nil {
		log.Println(err)
	}
}

/*func main() {
	dsn := "root:123456@tcp(127.0.0.1:3306)/gva?charset=utf8mb4&parseTime=True&loc=Local"
	db, _ := gorm.Open(mysql.Open(dsn), &gorm.Config{})
	var plugin ebpfplugins.EbpfPlugins
	db.Where("id=?", 69).First(&plugin)
	fmt.Println(plugin)
	if err := ebpfplugins2.RunSinglePlugin(plugin.PluginPath); err != nil {
		log.Println(err)
	}
}//测试runSinglePlugin函数*/
func main() {
	initDb()
	var ebpf ebpfplugins2.EbpfpluginsService
	var id = request2.PluginInfo{69}
	if err := ebpf.LoadEbpfPlugins(id); err != nil {
		log.Println(err)
	}
}
