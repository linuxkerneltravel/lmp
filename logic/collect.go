package logic

import (
	"bufio"
	"context"
	"fmt"
	"os/exec"
	"syscall"
	"time"

	"lmp/models"

	"go.uber.org/zap"
)

func DoCollect(m models.ConfigMessage) (err error) {
	//todo:save all pids
	exitChan := make(chan bool, len(m.BpfFilePath))

	for _, filePath := range m.BpfFilePath {
		go execute(filePath, m.CollectTime, exitChan)
	}

	for i := 0; i < len(m.BpfFilePath); i++ {
		<-exitChan
	}

	return nil
}

func execute(filepath string, collectTime int, exitChan chan bool) {
	defer func() {
		if err := recover(); err != nil {
			zap.L().Error("error in execute routine, err:", zap.Error(err.(error)))
			fmt.Println("error in execute routine, err:", err)
		}
	}()

	cmd := exec.Command("sudo", "python", filepath)
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
		zap.L().Error("error in cmd.Start()", zap.Error(err))
		return
	}

	go func() {
		err = cmd.Wait()
		if err != nil {
			zap.L().Error("error in cmd.Wait()", zap.Error(err))
			return
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(collectTime)*time.Second)
	defer cancel()

	for {
		select {
		case <-ctx.Done():
			syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
			exitChan <- true
			return
		}
	}
}
