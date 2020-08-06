//
// Created by Zhenwen Xu
// Modified by Chenyu Zhao
//
package config

import (
	"flag"
	"os"

	"github.com/urfave/cli"
	"github.com/go-ini/ini"
)

// Config is a configuration interface
type Config interface {
	IsSet(name string) bool
	Bool(name string) bool
	Int(name string) int
	IntSlice(name string) []int
	Int64(name string) int64
	Int64Slice(name string) []int64
	String(name string) string
	StringSlice(name string) []string
	Uint(name string) uint
	Uint64(name string) uint64
	Set(name, value string) error
}

// Cfg type, the type that load the conf file
type Cfg struct {
	Raw *ini.File
}

var (
	initializers []func(Config)
	config       Config
	Auth         = os.Getenv("AUTH") == "true"
	Online       = flag.Bool("online", false, "online flag")
	InHost       string
	Outhost      string
	Port         string
	GrafanaIp    string
)

//for influxdb
//use const temporary, we have Cfg ahead
const (
	InfluxdbAddr     = "http://127.0.0.1:8086"
	InfluxdbUsername =  "root"
	InfluxdbPassword = "root1234"
)

// For static bpf files
const (
	DefaultCollectorPath = "/usr/libexec/lmp/collector/"
	BpfPathC             = "/usr/libexec/lmp/collector/vfsstat.c"
	BpfPathPy            = "/usr/libexec/lmp/collector/vfsstat.py"
	PluginPath			 = "./plugins/"

)

func IsSet(name string) bool           { return config.IsSet(name) }
func Bool(name string) bool            { return config.Bool(name) }
func Int(name string) int              { return config.Int(name) }
func IntSlice(name string) []int       { return config.IntSlice(name) }
func Int64(name string) int64          { return config.Int64(name) }
func Int64Slice(name string) []int64   { return config.Int64Slice(name) }
func String(name string) string        { return config.String(name) }
func StringSlice(name string) []string { return config.StringSlice(name) }
func Uint(name string) uint            { return config.Uint(name) }
func Uint64(name string) uint64        { return config.Uint64(name) }
func Set(name, value string) error     { return config.Set(name, value) }

// Value: utils.GetInternalIPv4Address(),
var Flags = []cli.Flag{
	cli.StringFlag{
		Name:  "inhost",
		Value: "0.0.0.0",
		Usage: "service listen inside ipaddress",
	},
	cli.StringFlag{
		Name:  "outhost",
		Value: "0.0.0.0",
		Usage: "service listen outside address",
	},
	cli.UintFlag{
		Name:  "port,p",
		Value: 8080,
		Usage: "service port",
	},
	cli.StringFlag{
		Name:  "mode,m",
		Value: "dev",
		Usage: "run mode",
	},
	cli.StringFlag{
		Name:  "datacenter,dc",
		Value: "",
		Usage: "datacenter",
	},
	cli.StringFlag{
		Name:  "config,c",
		Value: "",
		Usage: "configure file",
	},
	cli.IntFlag{
		Name: "rate_limit_redis_id",
	},
}

// AddInitializer Add a initializer, call on initialized
func AddInitializer(fc func(Config)) {
	initializers = append(initializers, fc)
}

// Initialize initialize process configure
func Initialize(c Config) {
	config = c
	// odpenv := os.Getenv("ODP_ENV")
	// fmt.Println(ODP_ENV)
	// initializeDatabase(c)

	for _, initFunc := range initializers {
		initFunc(c)
	}
}

func setDefault(config Config, name, value string) {
	if config.IsSet(name) {
		return
	}
	config.Set(name, value)
}
