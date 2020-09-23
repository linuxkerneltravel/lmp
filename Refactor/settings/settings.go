package settings

import (
	"fmt"
	"github.com/fsnotify/fsnotify"
	"github.com/spf13/viper"
)

var Conf = new(Config)

type Config struct {
	*AppConfig   `mapstructure:"app"`
	*LogConfig   `mapstructure:"log"`
	*MySQLConfig `mapstructure:"mysql"`
	*RedisConfig `mapstructure:"redis"`
}

type AppConfig struct {
	Name      string `mapstructure:"name"`
	Mode      string `mapstructure:"mode"`
	Version   string `mapstructure:"version"`
	Port      int    `mapstructure:"port"`
	StartTime string `mapstructure:"start_time"`
	MachineID int64  `mapstructure:"machine_id"`
}

type LogConfig struct {
	Level      string `mapstructure:"level"`
	Filename   string `mapstructure:"filename"`
	MaxSize    int    `mapstructure:"max_size"`
	MaxBackups int    `mapstructure:"max_backups"`
	MaxAge     int    `mapstructure:"max_age"`
}

type MySQLConfig struct {
	Host         string `mapstructure:"host"`
	Port         int    `mapstructure:"port"`
	User         string `mapstructure:"user"`
	Password     string `mapstructure:"password"`
	Dbname       string `mapstructure:"dbname"`
	MaxOpenConns int    `mapstructure:"max_open_conns"`
	MaxIdleConns int    `mapstructure:"max_idle_conns"`
}

type RedisConfig struct {
	Host string `mapstructure:"host"`
	Port int    `mapstructure:"port"`
	Db   int    `mapstructure:"db"`
}

func Init() (err error) {
	// 方式1：直接指定配置文件的路径，（相对路径或者绝对路径）
	// 相对路径：相对于可执行文件的路径
	// 绝对路径：系统中实际的文件路径
	// viper.SetConfigFile("./conf/config.yaml")
	// viper.SetConfigFile("/Users/...")

	// 方式2：指定配置文件名和配置文件的位置，viper自己查找可用的配置文件
	// 配置文件名不需要带后缀
	// 配置文件位置可以配置多个
	viper.SetConfigName("config") // 所以在目录下不要写同名字的配置文件，因为会混乱
	viper.AddConfigPath(".")
	// 下面这个基本是通过配置中心使用的，例如远程的etcd，告诉viper当前的数据使用什么格式去解析
	// viper.SetConfigType("yaml")

	// 查找并读取配置文件
	if err := viper.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); ok {
			// 配置文件未找到错误
			fmt.Println("viper.ReadInConfig() failed : ", err)
			return err
		}
	}

	// 把读取到的配置信息反序列化到Conf变量中
	if err := viper.Unmarshal(&Conf); err != nil {
		fmt.Println("viper.Unmarshal failed, err:", err)
	}
	// 支持热加载
	viper.WatchConfig()
	viper.OnConfigChange(func(e fsnotify.Event) {
		// 配置文件发生变化后会调用的回调函数, 这里就是重新序列化到 Conf 中去
		fmt.Println("Config file changed:", e.Name)
		if err := viper.Unmarshal(Conf); err != nil {
			fmt.Println("viper.Unmarshal failed, err:", err)
		}
	})

	return nil
}
