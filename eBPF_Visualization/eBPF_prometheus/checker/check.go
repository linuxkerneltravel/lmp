// Copyright 2023 The LMP Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// https://github.com/linuxkerneltravel/lmp/blob/develop/LICENSE
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// author: Gui-Yue
//
// 该文件用于对输入进行合法性检查以及对输入进行初步的处理。

package checker

import (
	"fmt"
	"github.com/urfave/cli/v2"
	"log"
	"os"
	"regexp"
	"strings"
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
	fullcommand := ctx.Args().Slice()
	full := strings.Join(fullcommand, " ")
	return full, nil
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

func RelatedBetweenData(content string) {

}
