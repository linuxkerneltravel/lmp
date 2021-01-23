package logic

import (
	"bufio"
	"context"
	"fmt"
	"os/exec"
	"strings"
	"syscall"
	"time"

	"lmp/models"
	"lmp/settings"

	"go.uber.org/zap"
)

func DoCollect(m models.ConfigMessage, dbname string) (err error) {
	// 得到当前的用户名，之后利用这个用户名作为influxdb的dbname
	//if err = influxdb.CreatDatabase(dbname); err != nil {
	//	zap.L().Error("ERROR in DoCollect:", zap.Error(err))
	//}
	bpfFilePath := fillFrontMessage(m)
	fmt.Println("logic collect is here:", m)
	for _, filePath := range bpfFilePath {
		//fmt.Println(m.)
		go execute(filePath, m, dbname)
	}

	return nil
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

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(m.CollectTime)*time.Second*60)
	defer cancel()
	go func() {
		for {
			select {
			case <-ctx.Done():
				syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
				return
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

func fillFrontMessage(m models.ConfigMessage) []string {
	var bpfFilePath []string
	if m.Data.Cpuutilize == true {
		bpfFilePath = append(bpfFilePath, settings.Conf.PluginConfig.Path+"cpuutilize.py")
	}
	if m.Data.Irq == true {
		bpfFilePath = append(bpfFilePath, settings.Conf.PluginConfig.Path+"irq.py")
	}
	if m.Data.Taskswitch == true {
		bpfFilePath = append(bpfFilePath, settings.Conf.PluginConfig.Path+"taskswitch.py")
	}
	if m.Data.Picknext == true {
		bpfFilePath = append(bpfFilePath, settings.Conf.PluginConfig.Path+"picknext.py")
	}
	if m.Data.Harddiskreadwritetime == true {
		bpfFilePath = append(bpfFilePath, settings.Conf.PluginConfig.Path+"harddiskreadwritetime.py")
	}
	if m.Data.Memusage == true {
		bpfFilePath = append(bpfFilePath, settings.Conf.PluginConfig.Path+"memusage.py")
	}

	return bpfFilePath
}
