package main

import (
	"fmt"
	"log"
	"net/http"
	"runtime"
	"time"

	"github.com/gorilla/mux"
)

func test_hello(w http.ResponseWriter, req *http.Request) {
	fmt.Fprintf(w, "hello\n")
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
	println("Hello", "菜鸟实战")

	startHttpServer()

	// 当前版本
	fmt.Printf("版本: %s \n", runtime.Version())
}
