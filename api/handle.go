package api

import (
	"fmt"
	"lmp/config"
	"lmp/pkg/model"

	"bufio"
	"github.com/cihub/seelog"
	"github.com/gin-gonic/gin"
	//"log"
	"net/http"
	"os/exec"
	"path"
	"strings"
)

func init() {
	SetRouterRegister(func(router *RouterGroup) {
		engine := router.Group("/api")

		engine.GET("/ping", Ping)
		engine.POST("/data/collect", Do_collect)
		engine.POST("/register", UserRegister)
		engine.POST("/login", UserLogin)
		engine.POST("/uploadfiles", LoadFiles)

	})
}

func Ping(c *Context) {
	c.JSON(200, gin.H{"message": "pong"})
}

func Do_collect(c *Context) {
	////生成配置
	//m := fillConfigMessage(c)
	//fmt.Println(m)
	//
	////根据配置生成文件
	//var bpffile sys.BpfFile
	//
	//bpffile.Generator(&m)
	//
	////执行文件
	//go execute(m)


	c.Redirect(http.StatusMovedPermanently, "http://"+config.GrafanaIp)
	return
}


func execute(m model.ConfigMessage) {
	collector := path.Join(config.DefaultCollectorPath, "collect.py")
	script := make([]string, 0)

	script = append(script, "-P")
	script = append(script, m.Pid)
	newScript := strings.Join(script, " ")
	cmd := exec.Command("sudo","python", collector, newScript)

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		seelog.Error(err)
		return
	}
	defer stdout.Close()
	go func() {
		scanner := bufio.NewScanner(stdout)
		for scanner.Scan() {
			line := scanner.Text()
			fmt.Println(line)
		}
	}()

	stderr, err := cmd.StderrPipe()
	if err != nil {
		seelog.Error(err)
		return
	}
	defer stderr.Close()
	go func() {
		scanner := bufio.NewScanner(stderr)
		for scanner.Scan() {
			line := scanner.Text()
			fmt.Println(line)
		}
	}()

	err = cmd.Start()
	if err != nil {
		seelog.Error(err)
		return
	}

	err = cmd.Wait()
	if err != nil {
		seelog.Error(err)
		return
	}
	seelog.Info("start extracting data...")
}

func fillConfigMessage(c *Context) model.ConfigMessage {
	var m model.ConfigMessage
	if _, ok := c.GetPostForm("dispatchingdelay"); ok {
		m.DispatchingDelay = true
	} else {
		m.DispatchingDelay = false
	}
	if _, ok := c.GetPostForm("waitingqueuelength"); ok {
		m.WaitingQueueLength = true
	} else {
		m.WaitingQueueLength = false
	}
	if _, ok := c.GetPostForm("softirqtime"); ok {
		m.SoftIrqTime = true
	} else {
		m.SoftIrqTime = false
	}
	if _, ok := c.GetPostForm("hardirqtime"); ok {
		m.HardIrqTime = true
	} else {
		m.HardIrqTime = false
	}
	if _, ok := c.GetPostForm("oncputime"); ok {
		m.OnCpuTime = true
	} else {
		m.OnCpuTime = false
	}
	if _, ok := c.GetPostForm("vfsstat"); ok {
		m.Vfsstat = true
	} else {
		m.Vfsstat = false
	}
	if pid, ok := c.GetPostForm("pid"); ok {
		m.Pid = pid
	} else {
		m.Pid = "-1"
	}

	return m
}

//用户注册处理器函数
func UserRegister(c *Context) {
	//接收前端传入的参数，并绑定到一个UserModel结构体变量中
	var user model.UserModel
	if err := c.ShouldBind(&user); err != nil {
		seelog.Error("err ->", err.Error())
		c.String(http.StatusBadRequest, "输入的数据不合法")
	}


	//接收数据合法后，存入数据库mysql
	/*
	passwordAgain := c.PostForm("password-again")
	if passwordAgain != user.Password {
		c.String(http.StatusBadRequest, "密码校验无效，两次密码不一致")
		log.Panicln("密码校验无效，两次密码不一致")
	}
	 */
	id := user.Save()
	seelog.Info("username", user.Username, "password", user.Password, "password again", user.PasswordAgain)

	seelog.Info("id is ", id)
	fmt.Println(id)
	fmt.Println(user)
	c.File(fmt.Sprintf("%s/login.html", "static"))
}

//用户登录处理器函数
func UserLogin(c *Context) {
	var user model.UserModel
	if e := c.Bind(&user); e != nil {
		seelog.Error("login 绑定错误", e.Error())
	}

	u := user.QueryByEmail()
	if u.Password == user.Password {
		seelog.Info("登录成功", u.Username)
		c.File(fmt.Sprintf("%s/index.html", "static"))
	}
}

func LoadFiles(c *Context) {
	//获取表单数据 参数为name值
	f, err := c.FormFile("bpffile")
	//错误处理
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": err,
		})
		return
	} else {
		// Save the plugin file to the plugins directory
		path := "plugins/"
		filePath := path + f.Filename

		c.SaveUploadedFile(f, filePath)
		//fmt.Println(f.Filename, f.Size)

		c.JSON(http.StatusOK, gin.H{
			"message": "OK",
		})
	}
}








