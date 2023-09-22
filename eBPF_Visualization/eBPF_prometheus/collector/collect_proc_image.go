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
// 为proc_image所适配的collector，实现对proc_image输出格式的支持。

package collector

import (
	"bufio"
	"ebpf_prometheus/checker"
	"ebpf_prometheus/dao"
	"ebpf_prometheus/prom_core"
	"github.com/urfave/cli/v2"
	"gopkg.in/yaml.v2"
	"io"
	"log"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"syscall"
	"time"
)

// Pro_Setting 定义了设置项，通过读取同目录下的proc_setting.yaml实现对基本信息的设置。
type Proc_Setting struct {
	Name        string `yaml:"proc_name"`
	Path        string `yaml:"proc_path"`
	Pid         string `yaml:"proc_pid"`
	Max_Records int    `yaml:"proc_max_records"`
}

var proc_imageCommand = cli.Command{
	Name:    "proc_image",
	Aliases: []string{"pro"},
	Usage:   "Special collect data out from proc_image",
	Action:  procCollect,
}

// Get_Setting 函数用于获取设置的信息
func Get_Setting(which string) (error, string, int) {
	currentDir, _ := os.Getwd()
	content, err := os.ReadFile(currentDir + "/collector/tmux_proc_setting.yaml")
	if err != nil {
		log.Fatalf("Error reading file: %v", err)
		return err, "", 0
	}
	command := ""
	maxrecords := 0
	if which == "proc" {
		var setting Proc_Setting
		err = yaml.Unmarshal(content, &setting)
		if err != nil {
			log.Fatalf("Error unmarshaling YAML :%v", err)
			return err, "", 0
		}

		command = setting.Path + " -p " + setting.Pid
		maxrecords = setting.Max_Records
	} else if which == "tmux" {
		var setting Tmux_Setting
		err = yaml.Unmarshal(content, &setting)
		if err != nil {
			log.Fatalf("Error unmarshaling YAML :%v", err)
			return err, "", 0
		}

		command = setting.Path + " -p " + setting.Pid
		maxrecords = setting.Max_Records
	} else {
		log.Fatalf("select setting failed.")
	}
	return nil, command, maxrecords
}

func procCollect(ctx *cli.Context) error {
	_, command, _ := Get_Setting("proc")
	return ProcRun(command)
}

// ProcRun 是收集器的主函数，通过goroutin的方式实现数据收集，重定向，与prom_core包实现通信。
func ProcRun(command string) error {
	cmdStr := CheckFileType(command)
	cmd := exec.Command("sh", "-c", cmdStr)

	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	stdout, err := cmd.StdoutPipe()
	log.Println("full command is :", cmdStr)
	if err != nil {
		log.Println("get stdout failed:", err)
	}

	go listenSystemSignals(cmd)

	mapchan := make(chan map[string]interface{}, 2)

	loc, _ := time.LoadLocation("Asia/Shanghai")
	currenttime := float64(time.Now().In(loc).UnixNano()) / 1e9

	pathlist := strings.Split(command, "/")
	is_proc, _ := regexp.MatchString(`proc`, pathlist[len(pathlist)-1])
	is_lifecycle, _ := regexp.MatchString(`lifecycle`, pathlist[len(pathlist)-1])
	is_lock, _ := regexp.MatchString(`lock`, pathlist[len(pathlist)-1])

	if is_proc || is_lifecycle {
		log.Println("This is lifecycle")
		_, _, maxrecords := Get_Setting("proc")
		go redirectProc(stdout, mapchan)

		procdata := prom_core.ProcMetrics{Max_records: maxrecords, NowTime: currenttime}
		sqlobj := &dao.Sqlobj{Tablename: "proc_image_data"}
		procdata.Sqlobj = sqlobj
		// process chan from redirectProc Stdout
		go procdata.BootProcService()

		go func() {
			for {
				select {
				case <-mapchan:
					procdata.Getorigindata(mapchan)
					if procdata.Sqlinted {
						procdata.UpdateSql()
					} else {
						procdata.Initsql()
					}
					procdata.UpdateRecords()
					<-mapchan
				default:
				}
			}
		}()

	} else if is_lock {
		log.Println("This is lock_image.")
		_, _, maxrecords := Get_Setting("tmux")
		go redirectTmux(stdout, mapchan)
		tmuxdata := prom_core.TmuxMetrics{Max_records: maxrecords, NowTime: currenttime}
		sqlobj := &dao.Sqlobj{Tablename: "tmux_data"}
		tmuxdata.Sqlobj = sqlobj
		go tmuxdata.BootProcService()
		go func() {
			for {
				select {
				case <-mapchan:
					tmuxdata.Getorigindata(mapchan)
					if tmuxdata.Sqlinted {
						tmuxdata.UpdateSql()
					} else {
						tmuxdata.Initsql()
					}
					tmuxdata.UpdateRecords()
					<-mapchan
				default:
				}
			}
		}()
	}

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

// redirectProc 实现数据重定向
func redirectProc(stdout io.ReadCloser, mapchan chan map[string]interface{}) {
	var onemap map[string]interface{}
	scanner := bufio.NewScanner(stdout)
	for scanner.Scan() {
		line := scanner.Text()
		line = checker.CutunexceptedSpace(line)
		if checker.IsProcOutput(line) {
			onemap = make(map[string]interface{})
			parms := strings.Fields(line)
			for _, value := range parms {
				parts := strings.Split(value, ":")
				onemap[parts[0]] = parts[1]
			}
			// log.Println(onemap)
			mapchan <- onemap
		} else {
			continue
		}
	}
}
