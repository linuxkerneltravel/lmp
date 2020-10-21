package logic

import (
	"bufio"
	"context"
	"fmt"
	"go.uber.org/zap"
	"lmp/models"
	"os/exec"
	"strings"
)

func DoCollect(ctx context.Context, m models.ConfigMessage, dbname string) (err error) {
	for _, filePath := range m.BpfFilePath {
		go executeCollect(ctx, filePath, m, dbname)
	}
	return nil
}

func executeCollect(ctx context.Context, filepath string, m models.ConfigMessage, dbname string) {
	select {
	case <-ctx.Done():
		return
	default:
		execute(filepath, m, dbname)
	}
}

func execute(filepath string, m models.ConfigMessage, dbname string) {
	var newScript string
	// If pidflag is true, then we should add the pid parameter
	script := make([]string, 0)
	if m.PidFlag == true {
		script = append(script, "-D")
		script = append(script, dbname)
		script = append(script, "-P")
		script = append(script, m.Pid)
		newScript = strings.Join(script, " ")
	} else {
		script = append(script, "-D")
		script = append(script, dbname)
		newScript = strings.Join(script, " ")
	}
	// fmt.Println(filepath)
	// fmt.Println("[ConfigMessage] :", m.PidFlag, m.Pid)
	// fmt.Println("[string] :", filepath, newScript)
	cmd := exec.Command("sudo", "python", filepath, newScript)

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
	zap.L().Info("start extracting data...")
}
