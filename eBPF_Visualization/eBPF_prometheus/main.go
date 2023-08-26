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
// 主函数

package main

import (
	"ebpf_prometheus/checker"
	"ebpf_prometheus/collector"
	"fmt"
	"github.com/urfave/cli/v2"
	"log"
	"os"
	"sort"
)

func main() {
	app := cli.NewApp()
	app.Name = "data-visual"
	app.Usage = `
	use this cli-tool to collect output data and Convert output data to standard prometheus data.
	here are two different sub-command : collect & ecli
	example:
		sudo data-visual collect ./vfsstat.py
		sudo data-visual proc_image
`
	err := collector.RunServices(func(nm string, svc *collector.Aservice) error {
		ins, err := svc.NewInst(nil)
		if err != nil {
			return err
		}
		cmd, ok := ins.(cli.Command)
		if !ok {
			fmt.Printf("service %s doesn't implement cli.Command\n", nm)
			return fmt.Errorf("service %s doesn't implement cli.Command\n", nm)
		}
		app.Commands = append(app.Commands, &cmd)
		return nil
	})
	sort.Sort(cli.CommandsByName(app.Commands))

	app.Before = doBeforeJob
	err = app.Run(os.Args)
	if err != nil {
		log.Fatal(err)
	}
}

func doBeforeJob(ctx *cli.Context) (err error) {
	checker.CheckNormalError(err)
	return nil
}
