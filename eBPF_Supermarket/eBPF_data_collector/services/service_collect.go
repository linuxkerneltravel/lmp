package services

import (
	"bufio"
	"fmt"
	"github.com/lmp/eBPF_Visualization/core_service/globalver"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"

	"github.com/lmp/eBPF_Visualization/core_service/common"
	"github.com/lmp/eBPF_Visualization/core_service/dao"
	"github.com/lmp/eBPF_Visualization/core_service/utils"

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
	filePath, err := utils.CollectCheck(ctx)
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

	indexStruct := common.NewTableInfoByFilename(filePath)
	dao.CreateTableByTableInfo(indexStruct)

	go listenToSystemSignals(cmd, indexStruct)
	go rediectStdout(stdout, indexStruct)
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

func getStdout(stdout io.ReadCloser) {
	scanner := bufio.NewScanner(stdout)
	for scanner.Scan() {
		line := scanner.Text()
		fmt.Println(line)
	}
}

func listenToSystemSignals(cmd *exec.Cmd, tableInfo *common.TableInfo) {
	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, os.Interrupt, os.Kill, syscall.SIGTERM)
	for {
		select {
		case <-signalChan:
			// todo: generate csv file
			_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
			//fmt.Println("接受到来自系统的信号：", sig)
			dao.GenerateCsvFile(tableInfo)
			globalver.DB.Close()
			os.Exit(1) //如果ctrl+c 关不掉程序，使用os.Exit强行关掉
		}
	}
}

func rediectStdout(stdout io.ReadCloser, tableInfo *common.TableInfo) {
	scanner := bufio.NewScanner(stdout)

	if scanner.Scan() {
		indexes := scanner.Text()
		fmt.Println(indexes)
		err := tableInfo.IndexProcess(indexes)
		if err != nil {
			fmt.Errorf("indexes is wrong")
			return
		}
	}

	err := dao.AddIndex2Table(tableInfo)
	if err != nil {
		return
	}

	for scanner.Scan() {
		line := scanner.Text()
		dao.SaveData(tableInfo, line)
		fmt.Println(line)
	}
}
