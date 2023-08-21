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
	"log"
	"math"
	"net/http"
	"strconv"
	"strings"
	"testing"

	"github.com/eswzy/eTrafficManager/bpf"
)

type testCase struct {
	weights   []float64
	repeatNum int64
}

const (
	targetIP   = "1.1.1.1"
	targetPort = "80"
)

var serverPortList = []string{
	"8001",
	"8002",
	"8003",
}

var repeatNum int64 = 10000

func TestWeight(t *testing.T) {
	go startServer(serverPortList[0])
	go startServer(serverPortList[1])
	go startServer(serverPortList[2])
	// go func() {
	//	c1 := exec.Command("cat", "/sys/kernel/debug/tracing/trace_pipe")
	//	c1.Stdout = os.Stdout
	//	_ = c1.Start()
	// }()

	for _, tc := range []testCase{
		{
			weights: []float64{
				0.33333,
				0.33333,
				0.33333,
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
				0.33333,
				0.33333,
				0.33333,
			},
			repeatNum: repeatNum,
		},
		{
			weights: []float64{
				0.2,
				0.3,
				0.5,
			},
			repeatNum: repeatNum,
		},
	} {
		progs, err := bpf.LoadProgram()
		if err != nil {
			fmt.Println("[ERROR] Loading program failed:", err)
			return
		}

		targetPortInt, err := strconv.Atoi(targetPort)
		if err != nil {
			panic(err)
		}
		progs.InsertServiceItem(targetIP, targetPortInt, len(serverPortList))
		for i := 0; i < len(serverPortList); i++ {
			progs.AutoInsertBackend(targetIP, targetPort, "127.0.0.1", serverPortList[i], i+1, tc.weights[i])
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
			}
		}

		fmt.Println("[INFO] Test is done...")
		progs.AutoDeleteService(targetIP, targetPortInt)
		progs.Close()
	}
}

type Router struct {
	Route map[string]map[string]http.HandlerFunc
}

func (r *Router) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	if f, ok := r.Route[request.Method][request.URL.Path]; ok {
		f(writer, request)
	}
}

func (r *Router) HandleFunc(method, path string, f http.HandlerFunc) {
	method = strings.ToUpper(method)
	if r.Route == nil {
		r.Route = make(map[string]map[string]http.HandlerFunc)
	}
	if r.Route[method] == nil {
		r.Route[method] = make(map[string]http.HandlerFunc)
	}
	r.Route[method][path] = f
}

func startServer(portStr string) {
	route := Router{}
	route.HandleFunc("GET", "/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, portStr)
	})

	log.Fatal(http.ListenAndServe("localhost:"+portStr, &route))
}
