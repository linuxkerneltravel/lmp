package checker

import (
	"fmt"
	"github.com/urfave/cli/v2"
	"log"
	"os"
	"regexp"
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
		log.Fatalln(err)
	}
}
