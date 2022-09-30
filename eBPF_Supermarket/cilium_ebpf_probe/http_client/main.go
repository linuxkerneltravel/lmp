package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"math/rand"
	"net"
	"net/http"
	"os"
	"time"
	//"time"
)

const url = "http://10.0.3.23:8099/api/hello"

func main() {
	count := flag.Int("count", 30, "The number of calls to make.")
	flag.Parse()
	timeTickerChan := time.Tick(time.Second * 1) //每1秒进行一次展示输出
	rand.Seed(time.Now().UnixNano())
	for {
		//*count = rand.Intn(500)
		*count = 1
		for i := 0; i < *count; i++ {
			client := &http.Client{
				Transport: &http.Transport{
					DialContext: (&net.Dialer{
						KeepAlive: 0, // 修改为 0 可以生效
					}).DialContext,
				}}
			resp, err := client.Get(url)
			ErrPrint(err)

			res, err := ioutil.ReadAll(resp.Body)
			ErrPrint(err)
			fmt.Println("response statuscode is", resp.StatusCode, " and res body is ", string(res))
			resp.Body.Close()
			time.Sleep(time.Duration(200) * time.Millisecond)
		}
		<-timeTickerChan
	}
}
func ErrPrint(err error) {
	if err != nil {
		log.Fatalln(err)
		os.Exit(1)
	}
}
