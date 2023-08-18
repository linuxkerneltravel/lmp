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
// 为tcpwatch所适配的collector，实现对tcpwatch输出格式的支持。

package collector

import (
	"bufio"
	"ebpf_prometheus/checker"
	"io"
	"log"
	"strings"
)

// RedirectTcpWatch 重定向tcpwatch的输出
func RedirectTcpWatch(stdout io.ReadCloser, mapchan chan []map[string]interface{}) {
	var maps []map[string]interface{}
	scanner := bufio.NewScanner(stdout)
	startcollect := 0
	var titles []string
	var commandindex = 0
	for scanner.Scan() {
		line := scanner.Text()
		if checker.IsTCPwatchFirst(line) {
			log.Printf("Title:%s\n", line)
			parms := strings.Fields(line)
			for _, value := range parms {
				if strings.ToUpper(value) != "COMM" {
					commandindex = commandindex + 1
				}
				one_map := make(map[string]interface{})
				one_map[value] = nil
				maps = append(maps, one_map)
				titles = append(titles, value)
				startcollect = 1
			}
		} else {
			if startcollect == 0 {
				continue
			}
			parms := strings.Fields(line)
			var special_parms []string
			if len(parms) != len(titles) {
				// log.Printf("title number: %d, content number:%d", len(titles), len(parms))
				var COMM string
				if len(parms) < len(titles) {
					continue
				}
				if checker.InvalidTcpData(line) {
					continue
				}
				log.Printf("Content:%s\n", line)
				for i, value := range parms {
					if i < commandindex-1 && i >= len(parms)-commandindex {
						special_parms = append(special_parms, value)
					} else if i == commandindex-1 {
						COMM = value
					} else if i < len(parms)-commandindex {
						COMM = COMM + " " + value
						special_parms = append(special_parms, COMM)
					}
				}
				newMap := make(map[string]interface{})
				mu.Lock()
				for i, value := range special_parms {
					newMap[titles[i]] = value
				}
				mu.Unlock()
				mapchan <- []map[string]interface{}{newMap}
			} else {
				log.Printf("Content:%s\n", line)
				newMap := make(map[string]interface{})
				mu.Lock()
				for i, value := range parms {
					newMap[titles[i]] = value
				}
				mu.Unlock()
				mapchan <- []map[string]interface{}{newMap}
			}
		}
	}
}
