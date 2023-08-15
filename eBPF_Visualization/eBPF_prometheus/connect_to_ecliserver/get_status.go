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
// 为ecli-client服务专门设计，以实现通过http访问的方式获取ecli启动的bpf程序的信息输出，以及通过接口的方式对ecli-server进行控制。

package connect_to_ecliserver

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strconv"
)

type RequesetBody struct {
	ID int `json:"id"`
}

func Get_Running_Program(address string) map[string]int {
	resp, err := http.Get(address)
	if err != nil {
		log.Printf("Get running list fialed:%v", err)
		return nil
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		log.Println("Get request return non-OK status:", resp.StatusCode)
		return nil
	}
	var data map[string][]map[string]string
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		log.Println("fail to decode JSON data:", err)
		return nil
	}
	result := make(map[string]int)
	// 将get方法获取的json数据转换成需要的形式:{"bpf_name":id}
	for _, v := range data {
		for _, kv := range v {
			id, err := strconv.Atoi(kv["id"])
			if err != nil {
				log.Println("failed to convert id to int", err)
				return nil
			}
			result[kv["name"]] = id
		}
	}
	return result
}

func Get_Data(address string, name string, specific map[string]int) {
	requestbody := RequesetBody{
		ID: specific[name],
	}
	jsonData, err := json.Marshal(requestbody)
	if err != nil {
		log.Println("Fail to marshal json data:", err)
		return
	}
	resp, err := http.Post(address, "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		log.Println("POST request failed:", err)
		return
	}
	defer resp.Body.Close()

	//读取响应的body
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Println("Failed to read response body:", err)
		return
	}
	fmt.Println(respBody)
}
