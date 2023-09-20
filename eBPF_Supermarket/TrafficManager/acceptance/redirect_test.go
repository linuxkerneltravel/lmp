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
// author: Woa <me@wuzy.cn>

package acceptance

import (
	"fmt"
	"io"
	"net/http"
	"testing"

	"lmp/eTrafficManager/bpf"
)

func TestRedirect(t *testing.T) {
	var serverPortList = []string{
		"8001",
		"8002",
		"8003",
		"8004",
		"8005",
	}

	var repeatNum int64 = 125000
	for _, s := range serverPortList {
		go startServer(s)
	}

	progs, err := bpf.LoadProgram()
	if err != nil {
		fmt.Println("[ERROR] Loading program failed:", err)
		return
	}
	s := bpf.Service{
		IP:          "1.1.1.1",
		Port:        "80",
		Possibility: 0.75,
	}
	b := []bpf.Backend{
		{
			IP:          "127.0.0.1",
			Port:        "8001",
			Possibility: 0.25,
		}, {
			IP:          "127.0.0.1",
			Port:        "8002",
			Possibility: 0.75,
		},
	}
	progs.AutoInsertService(s, b, bpf.WeightedAction, nil)

	s2 := bpf.Service{
		IP:   "127.0.0.1",
		Port: "8003",
	}
	b2 := []bpf.Backend{
		{
			IP:          "127.0.0.1",
			Port:        "8004",
			Possibility: 0.125,
		},
		{
			IP:          "127.0.0.1",
			Port:        "8005",
			Possibility: 0.125,
		},
	}

	progs.AutoInsertService(s2, b2, bpf.RedirectAction, []bpf.Service{s})

	err = progs.Attach()
	if err != nil {
		fmt.Println("[ERROR] Attaching failed:", err)
	}

	countBucket := make(map[string]int)

	for i := 0; i < int(repeatNum); i++ {
		client := &http.Client{
			Transport: &http.Transport{
				// We must set DisableKeepAlives, otherwise all requests will be in one HTTP connection
				DisableKeepAlives: true,
			},
		}

		url := "http://" + "127.0.0.1:8003"
		req, err := http.NewRequest("GET", url, nil)
		if err != nil {
			fmt.Println("Error creating request:", err)
			return
		}

		resp, err := client.Do(req)
		if err != nil {
			fmt.Println("Error sending request:", err)
			return
		}
		defer resp.Body.Close()

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			fmt.Println("Error reading response:", err)
			return
		}

		// fmt.Println("Response:", string(body))
		countBucket[string(body)] += 1
	}

	for i := 0; i < len(serverPortList); i++ {
		actualNumber := float64(countBucket[serverPortList[i]])
		fmt.Printf("For port: %s, got actualNumber: %d.\n", serverPortList[i], int64(actualNumber))
	}

	fmt.Println("[INFO] Test is done...")
	progs.AutoDeleteService(s, nil)
	progs.AutoDeleteService(s2, []bpf.Service{s})
	progs.Close()
}
