package services

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"

	"github.com/lmp/eBPF_Visualization/core_service/dataprocess"

	"github.com/urfave/cli"
)

func init() {
	svc := Service{
		Name:    "collectData",
		Desc:    "collect eBPF data",
		NewInst: newCollectCmd,
	}
	if err := AddService(&svc); err != nil {
		fmt.Printf("Failed to load collect service : %s\n", err)
		return
	}
}

var collectCommand = cli.Command{
	Name:   "collect",
	Usage:  "collect system data by eBPF",
	Action: serviceCollect,
}

func newCollectCmd(ctx *cli.Context, opts ...interface{}) (interface{}, error) {
	return collectCommand, nil
}

func serviceCollect(ctx *cli.Context) error {
	filePath, err := collectCheck(ctx)
	if err != nil {
		return err
	}
	return Run(filePath)
}

func Run(filePath string) error {
	cmdSlice := make([]string, 0)
	// todo: run as root
	cmdSlice = append(cmdSlice, "sudo")
	cmdSlice = append(cmdSlice, "stdbuf")
	cmdSlice = append(cmdSlice, "-oL")
	cmdSlice = append(cmdSlice, filePath)

	cmdStr := strings.Join(cmdSlice, " ")
	cmd := exec.Command("sh", "-c", cmdStr)

	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	stderr, _ := cmd.StderrPipe()
	stdout, _ := cmd.StdoutPipe()

	go listenToSystemSignals(cmd)
	go rediectStdout(stdout, filePath)
	go getStdout(stderr)

	err := cmd.Start()
	if err != nil {
		fmt.Errorf("cmd.Start() analysis service failed: %v", err)
		os.Exit(-1)
	}

	err = cmd.Wait()
	if err != nil {
		fmt.Errorf("cmd.Run() analysis failed with: %v", err)
		os.Exit(-1)
	}

	return nil
}

func collectCheck(ctx *cli.Context) (string, error) {
	if err := CheckArgs(ctx, 1, ConstExactArgs); err != nil {
		return "", err
	}

	file := ctx.Args().Get(0)
	if !IsInputStringValid(file) {
		return "", fmt.Errorf("input:%s is invalid", file)
	}

	exist, err := PathExist(file)
	if err != nil {
		return "", err
	}
	if !exist {
		return "", fmt.Errorf("file %s is not exist", file)
	}
	return file, nil
}

func getStdout(stdout io.ReadCloser) {
	scanner := bufio.NewScanner(stdout)
	for scanner.Scan() {
		line := scanner.Text()
		fmt.Println(line)
	}
}

func listenToSystemSignals(cmd *exec.Cmd) {
	signalChan := make(chan os.Signal, 1)

	signal.Notify(signalChan, os.Interrupt, syscall.SIGTERM)
	<-signalChan
	// todo: generate csv file
	_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	os.Exit(100)
}

func rediectStdout(stdout io.ReadCloser, filePath string) {
	scanner := bufio.NewScanner(stdout)
	indexStruct := dataprocess.NewIndexStruct(filePath)

	if scanner.Scan() {
		indexes := scanner.Text()
		err := indexStruct.IndexProcess(indexes)
		if err != nil {
			fmt.Errorf("indexes is wrong")
			return
		}
	}

	for scanner.Scan() {
		line := scanner.Text()
		parms := strings.Fields(line)
		fmt.Println(parms)
		// todo: rediect data to db
		// 1. parse the number of the index

		// 2. save index
		// 3. create table
		// 4. save data to db
	}
}
