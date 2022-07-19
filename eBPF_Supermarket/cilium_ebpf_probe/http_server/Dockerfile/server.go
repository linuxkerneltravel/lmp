package main

import (
	"encoding/json"
	"fmt"
	"github.com/gorilla/mux"
	"log"
	"net/http"
	"runtime"
	"time"
)

func test_hello(w http.ResponseWriter, req *http.Request) {
	url, _ := json.Marshal(req.URL)
	println("A Request URL:", string(url))
	fmt.Printf(" and User Agent: %s\n", req.Header.Get("User-Agent"))
	fmt.Fprintf(w, "Resonse:")
	w.Write([]byte("hello"))
}

func startHttpServer() {

	//路由
	router := mux.NewRouter()

	//通过完整的path来匹配
	router.HandleFunc("/api/hello", test_hello)

	// 初始化
	srv := &http.Server{
		Handler:      router,
		Addr:         ":8099",
		WriteTimeout: 15 * time.Second,
		ReadTimeout:  15 * time.Second,
	}

	log.Fatal(srv.ListenAndServe())
}

func main() {
	// 使用内置函数打印
	println("Listning on 8099...")

	startHttpServer()

	// 当前版本
	fmt.Printf("版本: %s \n", runtime.Version())
}
