package main

import (
	"encoding/json"
	"fmt"
	"github.com/gorilla/mux"
	"log"
	"math/rand"
	"net/http"
	"runtime"
	"time"
)

type responseStruct struct {
	code int
	msg  string
}

var (
	CodeMessage map[int]responseStruct
)

func test_hello(w http.ResponseWriter, req *http.Request) {

	rand.Seed(time.Now().UnixNano())
	num := rand.Intn(20)
	if num >= 6 {
		num = 0
	}
	url, _ := json.Marshal(req.URL)
	println("A Request URL:", string(url))
	fmt.Printf(" and User Agent: %s\n", req.Header.Get("User-Agent"))

	w.WriteHeader(CodeMessage[num].code)
	fmt.Fprintf(w, "Resonse:")
	w.Write([]byte(CodeMessage[num].msg))
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
	CodeMessage = make(map[int]responseStruct)
	CodeMessage[0] = responseStruct{code: 200, msg: "The request was successful."}
	CodeMessage[1] = responseStruct{code: 400, msg: "Bad Request."}
	CodeMessage[2] = responseStruct{code: 401, msg: "Unauthorized"}
	CodeMessage[3] = responseStruct{code: 404, msg: "Not Found."}
	CodeMessage[4] = responseStruct{code: 502, msg: "Bad Gateway."}
	CodeMessage[5] = responseStruct{code: 504, msg: "Gateway Time-out."}
	println("Listning on 8099 and init errcode map...")

	startHttpServer()

	// 当前版本
	fmt.Printf("版本: %s \n", runtime.Version())
}
