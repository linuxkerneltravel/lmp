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
	for _, filePath := range m.BpfFilePath {
		//fmt.Println(m.)
		go execute(filePath, m)
	}

	return nil
}

func execute(filepath string, m models.ConfigMessage) {
	defer func() {
		if err := recover(); err != nil {
			zap.L().Error("error in execute routine, err:", zap.Error(err.(error)))
			fmt.Println("error in execute routine, err:", err)
		}
	}()

	cmd := exec.Command("sudo", "python", filepath)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(m.CollectTime)*time.Second)
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
