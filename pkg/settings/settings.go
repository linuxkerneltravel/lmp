package settings

import (
	"fmt"

	"github.com/fsnotify/fsnotify"
	"github.com/spf13/viper"
)

const (
	Name     = "LMP"
	Version  = "v0.0.1"
	LmpUsage = `LMP is a web tool for real-time display of Linux system performance data based on BCC (BPF Compiler Collection). 
To get more info of how to use lmp:
	# lmp help
`
)

var Conf = new(Config)

type Config struct {
	*AppConfig      `mapstructure:"app"`
	*LogConfig      `mapstructure:"log"`
	*MySQLConfig    `mapstructure:"mysql"`
	*InfluxdbConfig `mapstructure:"influxdb"`
	*RedisConfig    `mapstructure:"redis"`
	*PluginConfig   `mapstructure:"Plugin"`
	*GrafanaConfig  `mapstructure:"grafana"`
}

type AppConfig struct {
	Mode      string `mapstructure:"mode"`
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

type InfluxdbConfig struct {
	Host     string `mapstructure:"host"`
	Port     int    `mapstructure:"port"`
	User     string `mapstructure:"user"`
	Password string `mapstructure:"password"`
	Dbname   string `mapstructure:"dbname"`
}

type RedisConfig struct {
	Host string `mapstructure:"host"`
	Port int    `mapstructure:"port"`
	Db   int    `mapstructure:"db"`
}

type PluginConfig struct {
	Path        string `mapstructure:"path"`
	CollectTime int    `mapstructure:"collecttime"`
}

type GrafanaConfig struct {
	IP string `mapstructure:"ip"`
}

func Init() (err error) {
	// 在目录下不要写同名字的配置文件，否则会混乱
	viper.SetConfigName("config")
	viper.AddConfigPath(".")

	if err := viper.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); ok {
			fmt.Println("viper.ReadInConfig() failed : ", err)
			return err
		}
	}

	if err := viper.Unmarshal(&Conf); err != nil {
		fmt.Println("viper.Unmarshal failed, err:", err)
	}

	viper.WatchConfig()
	viper.OnConfigChange(func(e fsnotify.Event) {
		fmt.Println("Config file changed:", e.Name)
		if err := viper.Unmarshal(Conf); err != nil {
			fmt.Println("viper.Unmarshal failed, err:", err)
		}
	})

	return nil
}
