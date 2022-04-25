package utils

import (
	"fmt"
	"github.com/urfave/cli"
	"log"
	"os"
	"regexp"
)

const (
	ConstExactArgs = iota
	ConstMinArgs
)

const (
	MaxFileSize int64 = 100 * 1024 * 1024
)

func CollectCheck(ctx *cli.Context) (string, error) {
	//if err := CheckArgs(ctx, 1, ConstExactArgs); err != nil {
	//	return "", err
	//}

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

func IsInputStringValid(input string) bool {
	if input != "" {
		if isOk, _ := regexp.MatchString("^[a-zA-Z0-9/._-]*$", input); isOk {
			return isOk
		}
	}
	return false
}

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

func CheckNormalError(err error) {
	if err != nil {
		log.Fatal(err)
	}
}
