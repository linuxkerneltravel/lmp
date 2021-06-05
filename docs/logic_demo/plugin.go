package logic

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"syscall"
	"time"
)

// 插件状态
type PluginState uint8

const (
	PgStateSleeping PluginState = iota
	PgStateRunning
	PgStateInvalid
)

// 插件类型
type PluginType uint8

const (
	PgTypeCebpf PluginType = iota
	PgTypeBcc
	PgTypeShell
)

// 与插件类型对应的Args
var typeArgsMap = map[PluginType]string{
	PgTypeCebpf: "",
	PgTypeBcc:   "python3",
	PgTypeShell: "/bin/bash -c",
}

// 与插件类型对应的string
var strTypeMap = map[string]PluginType{
	"Cebpf": PgTypeCebpf,
	"Bcc":   PgTypeBcc,
	"Shell": PgTypeShell,
}

// 插件
type Plugin struct {
	PgType   PluginType  // 插件类型
	PgState  PluginState // 插件状态
	ExecPath string      // 可执行文件路径
	RunTime  uint32      // 此次执行时间
}

// 插件执行前的异常检查
func (pg *Plugin) PrepareRun(runtime uint32) error {
	if pg.PgState == PgStateSleeping {
		pg.PgState = PgStateRunning
		pg.RunTime = runtime
	}

	if pg.PgState == PgStateRunning {
		return errors.New("this plugin is running")
	}

	if pg.PgState == PgStateInvalid {
		return errors.New("this plugin is invalid")
	}

	return nil
}

// 插件执行完或者插件执行失败后进行设置
func (pg *Plugin) ExitRun(err error) {
	if err != nil {
		pg.PgState = PgStateInvalid
	} else {
		pg.PgState = PgStateSleeping
	}

	pg.RunTime = 0
}

// 插件的具体执行
func (pg *Plugin) Run(runtime uint32, exitChan chan bool) {
	err := pg.PrepareRun(runtime)
	if err != nil {
		exitChan <- true
		return
	}

	cmd := exec.Command("sudo", typeArgsMap[pg.PgType], pg.ExecPath)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}

	stdout, err := cmd.StdoutPipe()
	defer stdout.Close()
	go func() {
		scanner := bufio.NewScanner(stdout)
		for scanner.Scan() {
			line := scanner.Text()
			fmt.Println(line)
		}
	}()

	stderr, err := cmd.StderrPipe()
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
		exitChan <- true
		pg.ExitRun(err)
		return
	}

	go func() {
		err := cmd.Wait()
		if err != nil {
			// 日志
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(runtime)*time.Minute)
	defer cancel()

	for {
		select {
		case <-ctx.Done():
			syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
			exitChan <- true
			pg.ExitRun(nil)
			return
		}
	}
}
