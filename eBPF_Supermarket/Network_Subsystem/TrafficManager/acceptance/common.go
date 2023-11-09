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
	"log"
	"net/http"
	"strings"
)

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
