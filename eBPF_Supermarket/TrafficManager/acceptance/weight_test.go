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
	"math"
	"net/http"
	"testing"

	"lmp/eTrafficManager/bpf"
)

func TestWeight(t *testing.T) {
	const (
		targetIP   = "1.1.1.1"
		targetPort = "80"
	)

	var serverPortList = []string{
		"7001",
		"7002",
		"7003",
	}

	var repeatNum int64 = 10000

	go startServer(serverPortList[0])
	go startServer(serverPortList[1])
	go startServer(serverPortList[2])
	// go func() {
	//	c1 := exec.Command("cat", "/sys/kernel/debug/tracing/trace_pipe")
	//	c1.Stdout = os.Stdout
	//	_ = c1.Start()
	// }()

	for _, tc := range []struct {
		weights   []float64
		repeatNum int64
	}{
		{
			weights: []float64{
				1,
				0,
				0,
			},
			repeatNum: repeatNum,
		},
		{
			weights: []float64{
				0,
				1,
				0,
			},
			repeatNum: repeatNum,
		},
		{
			weights: []float64{
				0,
				0,
				1,
			},
			repeatNum: repeatNum,
		},
		{
			weights: []float64{
				0.25,
				0.75,
				0,
			},
			repeatNum: repeatNum,
		},
		{
			weights: []float64{
				0.75,
				0.25,
				0,
			},
			repeatNum: repeatNum,
		},
		{
			weights: []float64{
				0.25,
				0.25,
				0.5,
			},
			repeatNum: repeatNum,
		},
		{
			weights: []float64{
				0.125,
				0.25,
				0.625,
			},
			repeatNum: repeatNum,
		},
	} {
		progs, err := bpf.LoadProgram()
		if err != nil {
			fmt.Println("[ERROR] Loading program failed:", err)
			return
		}

		progs.InsertServiceItem(targetIP, targetPort, len(serverPortList), bpf.WeightedAction)
		totalPercentage := 0.0
		for i := 0; i < len(serverPortList); i++ {
			totalPercentage += tc.weights[i]
			progs.AutoInsertBackend(targetIP, targetPort, "127.0.0.1", serverPortList[i], i+1, tc.weights[i], totalPercentage)
		}
		if math.Abs(totalPercentage-1) > 0.005 {
			fmt.Printf("[WARNING] Total weight for service %s:%s is not 1, but %f.\n", targetIP, targetPort, totalPercentage)
		}

		err = progs.Attach()
		if err != nil {
			fmt.Println("[ERROR] Attaching failed:", err)
		}

		countBucket := make(map[string]int)

		for i := 0; i < int(tc.repeatNum); i++ {
			client := &http.Client{
				Transport: &http.Transport{
					// We must set DisableKeepAlives, otherwise all requests will be in one HTTP connection
					DisableKeepAlives: true,
				},
			}

			url := "http://" + targetIP
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
			expectNumber := tc.weights[i] * float64(tc.repeatNum)
			actualNumber := float64(countBucket[serverPortList[i]])
			if math.Abs(actualNumber-expectNumber)/expectNumber > 0.05 {
				t.Errorf("For port: %s, expectNumber: %f, but actualNumber: %d, rate: %f. Maybe retesting will fix this", serverPortList[i], expectNumber, int64(actualNumber), math.Abs(actualNumber-expectNumber)/expectNumber)
			} else {
				fmt.Printf("For port: %s, expectNumber: %f, got actualNumber: %d, rate: %f.\n", serverPortList[i], expectNumber, int64(actualNumber), math.Abs(actualNumber-expectNumber)/expectNumber)
			}
		}

		fmt.Println("[INFO] Test is done...")
		s := bpf.Service{
			IP:   targetIP,
			Port: targetPort,
		}
		progs.AutoDeleteService(s, nil)
		progs.Close()
	}
}
