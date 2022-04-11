package services

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"regexp"
	"syscall"

	"github.com/urfave/cli"
)

// the number of args
const (
	ConstExactArgs = iota
	ConstMinArgs
)

//file attribute
const (
	MaxFileSize int64 = 100 * 1024 * 1024
)

// CheckArgs method check command args num
func CheckArgs(context *cli.Context, expected, checkType int) error {
	var err error
	cmdName := context.Command.Name
	switch checkType {
	case ConstExactArgs:
		if context.NArg() != expected {
			err = fmt.Errorf("%s: %q requires exactly %d argument(s)", os.Args[0], cmdName, expected)
		}
	case ConstMinArgs:
		if context.NArg() < expected {
			err = fmt.Errorf("%s: %q requires a minimum of %d argument(s)", os.Args[0], cmdName, expected)
		}
	}

	if err != nil {
		fmt.Printf("Incorrect Usage.\n")
		_ = cli.ShowCommandHelp(context, cmdName)
		return err
	}
	return nil
}

// IsInputStringValid: common input string validator
func IsInputStringValid(input string) bool {
	if input != "" {
		if isOk, _ := regexp.MatchString("^[a-zA-Z0-9/._-]*$", input); isOk {
			return isOk
		}
	}
	return false
}

// PathExist method check path if exist or not
func PathExist(path string) (bool, error) {
	fileInfo, err := os.Stat(path)
	if err == nil {
		if !fileInfo.IsDir() && fileInfo.Size() > MaxFileSize {
			return true, fmt.Errorf("the size of %s exceeds"+
				" the maximum value which is %d", fileInfo.Name(), MaxFileSize)
		}
		return true, nil
	}
	if os.IsNotExist(err) {
		return false, nil
	}
	return false, err
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
	_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	os.Exit(100)
}
