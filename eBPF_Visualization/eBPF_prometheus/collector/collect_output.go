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
// 该文件用于将收集到的信息进行进行规范化处理，实现重定向，并与Prometheus可视化逻辑进行交互。

package collector

import (
	"bufio"
	"ebpf_prometheus/checker"
	"ebpf_prometheus/prom_core"
	"fmt"
	"github.com/urfave/cli/v2"
	"io"
	"log"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"sync"
	"syscall"
)

const firstline = int(1)

type Aservice struct {
	Name    string
	Desc    string
	NewInst func(ctx *cli.Context, opts ...interface{}) (interface{}, error)
}

var GlobalServices = struct {
	sync.RWMutex
	services map[string]*Aservice
}{}

func AddAService(svc *Aservice) error {
	GlobalServices.Lock()
	defer GlobalServices.Unlock()

	GlobalServices.services = make(map[string]*Aservice)

	if _, existed := GlobalServices.services[svc.Name]; existed {
		return fmt.Errorf("service existed: %s", svc.Name)
	}

	GlobalServices.services[svc.Name] = svc

	return nil
}

func RunServices(fn func(nm string, svc *Aservice) error) error {
	GlobalServices.Lock()
	defer GlobalServices.Unlock()

	for name, service := range GlobalServices.services {
		if err := fn(name, service); err != nil {
			return err
		}
	}
	return nil
}

var collectCommand = cli.Command{
	Name:    "collect",
	Aliases: []string{"c"},
	Usage:   "collect system data by eBPF",
	Action:  simpleCollect,
}

func init() {
	svc := Aservice{
		Name:    "collectData",
		Desc:    "collect eBPF data",
		NewInst: newCollectCmd,
	}
	if err := AddAService(&svc); err != nil {
		log.Fatalf("Failed to load ... error:%s\n", err)
		return
	}
}

func newCollectCmd(ctx *cli.Context, opts ...interface{}) (interface{}, error) {
	return collectCommand, nil
}

func simpleCollect(ctx *cli.Context) error {
	filePath, err := checker.CollectCheck(ctx)
	if err != nil {
		return err
	}
	return Run(filePath)
}

func CheckFileType(filePath string) (specificcommand string) {
	cmdSlice := make([]string, 0)
	cmdSlice = append(cmdSlice, "sudo")
	cmdSlice = append(cmdSlice, "stdbuf")
	cmdSlice = append(cmdSlice, "-oL")
	lowercaseFilename := strings.ToLower(filePath)
	if strings.HasSuffix(lowercaseFilename, ".py") {
		log.Println("Try to run a python program.")
		cmdSlice = append(cmdSlice, "python3")
		cmdSlice = append(cmdSlice, "-u")
		cmdSlice = append(cmdSlice, filePath)
		cmdStr := strings.Join(cmdSlice, " ")
		return cmdStr
	} else {
		cmdSlice = append(cmdSlice, filePath)
		cmdStr := strings.Join(cmdSlice, " ")
		return cmdStr
	}
}

func Run(filePath string) error {
	cmdStr := CheckFileType(filePath)
	cmd := exec.Command("sh", "-c", cmdStr)

	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	stdout, err := cmd.StdoutPipe()
	log.Println("full command is :", cmdStr)
	if err != nil {
		log.Println("get stdout failed:", err)
	}

	go listenSystemSignals(cmd)
	//go getStdout(stdout)

	mapchan := make(chan []map[string]interface{}, 2)
	go rediectStdout(stdout, mapchan)
	// process chan from redirect Stdout
	go func() {
		for {
			select {
			case <-mapchan:
				prom_core.StartService(mapchan)
				<-mapchan
			default:
			}
		}
	}()

	err = cmd.Start()
	if err != nil {
		log.Printf("cmd.Start() analysis service failed: %v", err)
		os.Exit(-1)
	}

	err = cmd.Wait()
	if err != nil {
		log.Printf("cmd.Run() analysis failed with: %v", err)
		os.Exit(-1)
	}

	return nil
}

func listenSystemSignals(cmd *exec.Cmd) {
	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, os.Interrupt, os.Kill, syscall.SIGTERM)
	for {
		select {
		case <-signalChan:
			_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
			os.Exit(1)
		}
	}
}

func rediectStdout(stdout io.ReadCloser, mapchan chan []map[string]interface{}) {
	var maps []map[string]interface{}
	scanner := bufio.NewScanner(stdout)
	var titles []string
	var line_number = 1
	for scanner.Scan() {
		line := scanner.Text()
		if line_number == firstline {
			log.Printf("Title:%s\n", line)
			parms := strings.Fields(line)
			for _, value := range parms {
				one_map := make(map[string]interface{})
				one_map[value] = nil
				maps = append(maps, one_map)
				titles = append(titles, value)
			}
		} else {
			log.Printf("Content:%s\n", line)
			parms := strings.Fields(line)
			for i, value := range parms {
				maps[i][titles[i]] = value
			}
			mapchan <- maps
		}
		line_number += 1
	}
}
