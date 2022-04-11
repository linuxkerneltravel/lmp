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
	Name:      "collect",
	Usage:     "collect system data by eBPF",
	ArgsUsage: "[APP_NAME]",
	//Flags: []cli.Flag{
	//	cli.StringFlag{
	//		Name:  "model, m",
	//		Usage: "specified the self trained model to analysis",
	//		Value: "",
	//	},
	//	cli.BoolFlag{
	//		Name:  "characterization, c",
	//		Usage: "only analysis the workload type",
	//	},
	//},
	//Description: func() string {
	//	desc := `
	// analysis the system's workload type and optimization performance.
	// you can specified the app name, but it's just for reference only.
	//     example: atune-adm analysis mysql
	// you can specify the self trained model to analysis, which only
	// can be end with .m.
	//     example: atune-adm analysis --model ./self_trained.m
	// you can only analysis the workload type.
	//     example: atune-adm analysis --characterization
	//you can specify the collecting times.
	//     example: atune-adm analysis -t 5
	// you can specify the script to be executed.
	//     example: atune-adm analysis -s script.sh`
	//	return desc
	//}(),
	Action: serviceCollect,
}

func newCollectCmd(ctx *cli.Context, opts ...interface{}) (interface{}, error) {
	return collectCommand, nil
}

func serviceCollect(ctx *cli.Context) error {
	// check file if not exist
	return Run("sudo", "stdbuf", "-oL", "./vfsstat")
}

func Run(command string, path ...string) error {
	cmd := exec.Command(command, path...)

	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	stderr, _ := cmd.StderrPipe()
	stdout, _ := cmd.StdoutPipe()

	go listenToSystemSignals(cmd)
	go logStdout(stdout)
	go logStdout(stderr)

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

func listenToSystemSignals(cmd *exec.Cmd) {
	signalChan := make(chan os.Signal, 1)

	signal.Notify(signalChan, os.Interrupt, syscall.SIGTERM)
	<-signalChan
	_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	os.Exit(100)
}

func logStdout(stdout io.ReadCloser) {
	scanner := bufio.NewScanner(stdout)
	for scanner.Scan() {
		line := scanner.Text()
		parms := strings.Fields(line)
		fmt.Println(parms)
	}
}
