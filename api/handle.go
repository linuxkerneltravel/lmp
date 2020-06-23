package api

import (
	//"context"
	"fmt"
	"lmp/config"
	"lmp/deployments/sys"
	"lmp/pkg/model"
	//"log"
	"net/http"
	"os/exec"
	"path"
	"github.com/cihub/seelog"
	"github.com/gin-gonic/gin"
	"strings"
	"bufio"
)

func init() {
	SetRouterRegister(func(router *RouterGroup) {
		engine := router.Group("/api")

		engine.GET("/ping", Ping)
		engine.POST("/data/collect", Do_collect)
		engine.POST("/register", UserRegister)
	})
}

func Do_collect(c *Context) {
	//生成配置
	m := fillConfigMessage(c)
	fmt.Println(m)

	//根据配置生成文件
	var bpffile sys.BpfFile

	bpffile.Generator(&m)

	//执行文件
	go execute(m)

	c.Redirect(http.StatusMovedPermanently, "http://"+config.GrafanaIp)
	return
}

func Ping(c *Context) {
	c.JSON(200, gin.H{"message": "pong"})
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
	var user model.UserModel
	if err := c.ShouldBind(&user); err != nil {
		seelog.Error("err ->", err.Error())
		c.String(http.StatusBadRequest, "输入的数据不合法")
	}
	seelog.Info("username", user.Username, "password", user.Password, "password again", user.PasswordAgain)
	fmt.Println(user)
	//c.Redirect(http.StatusMovedPermanently, "/")
}
