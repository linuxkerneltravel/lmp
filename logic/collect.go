package logic

import (
	"bufio"
	"context"
	"fmt"
	"go.uber.org/zap"
	"lmp/dao/influxdb"
	"lmp/models"
	"os/exec"
	"strings"
	"syscall"
	"time"
)

func DoCollect(m models.ConfigMessage, dbname string) (err error) {
	// 得到当前的用户名，之后利用这个用户名作为influxdb的dbname
	if err = influxdb.CreatDatabase(dbname); err != nil {
		zap.L().Error("ERROR in DoCollect:", zap.Error(err))
	}

	fmt.Println(m)
	for _, filePath := range m.BpfFilePath {
		go execute(filePath, m, dbname)
	}

	if m.Netlatency == true {
		go netExecute(m)
	}

	return nil
}

func netExecute(m models.ConfigMessage) {
	var newScript string
	// If pidflag is true, then we should add the pid parameter
	script := make([]string, 0)
	script = append(script, ">")
	script = append(script, "./net.txt")
	newScript = strings.Join(script, " ")

	//fmt.Println(filepath)
	//fmt.Println("[ConfigMessage] :", m.PidFlag, m.Pid)
	//fmt.Println("[string] :", filepath, newScript)
	cmd := exec.Command("sudo", "python", "./plugins/netlatency.py", newScript)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(m.CollectTime)*time.Second)
	defer cancel()
	go func() {
		for {
			select {
			case <-ctx.Done():
				syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
				return
			default:
			}

		}
	}()

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		zap.L().Error("error in cmd.StdoutPipe()", zap.Error(err))
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
		zap.L().Error("error in cmd.StderrPipe()", zap.Error(err))
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
		zap.L().Error("error in cmd.Start()", zap.Error(err))
		return
	}

	err = cmd.Wait()
	if err != nil {
		zap.L().Error("error in cmd.Wait()", zap.Error(err))
		return
	}
}

func execute(filepath string, m models.ConfigMessage, dbname string) {
	var newScript string
	// If pidflag is true, then we should add the pid parameter
	script := make([]string, 0)
	script = append(script, "-D")
	script = append(script, dbname)
	newScript = strings.Join(script, " ")
	//fmt.Println(filepath)
	//fmt.Println("[ConfigMessage] :", m.PidFlag, m.Pid)
	//fmt.Println("[string] :", filepath, newScript)
	cmd := exec.Command("sudo", "python", filepath, newScript)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(m.CollectTime)*time.Second)
	defer cancel()
	go func() {
		for {
			select {
			case <-ctx.Done():
				syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
				return
			default:
			}

		}
	}()

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		zap.L().Error("error in cmd.StdoutPipe()", zap.Error(err))
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
		zap.L().Error("error in cmd.StderrPipe()", zap.Error(err))
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
		zap.L().Error("error in cmd.Start()", zap.Error(err))
		return
	}

	err = cmd.Wait()
	if err != nil {
		zap.L().Error("error in cmd.Wait()", zap.Error(err))
		return
	}
}
