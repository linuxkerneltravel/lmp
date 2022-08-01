package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"
	//"time"
)

const url = "http://localhost:8099/api/hello"

func main() {
	count := flag.Int("count", 5, "The number of calls to make.")
	flag.Parse()
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
		//time.Sleep(time.Duration(100) * time.Millisecond)
	}

}
func ErrPrint(err error) {
	if err != nil {
		log.Fatalln(err)
		os.Exit(1)
	}
}
