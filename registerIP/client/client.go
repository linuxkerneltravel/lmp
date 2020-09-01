package main

import (
	"context"
	"fmt"
	"google.golang.org/grpc"
	"lmp-grpc/registerIP/message"
	"net"
	"os"
)

func GetIntranetIp() {
	addrs, err := net.InterfaceAddrs()

	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	for _, address := range addrs {

		// 检查ip地址判断是否回环地址
		if ipnet, ok := address.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
			if ipnet.IP.To4() != nil {
				fmt.Println("ip:", ipnet.IP.String())
			}

		}
	}
}

func main() {
	// Connect to server
	conn, err := grpc.Dial(":8080", grpc.WithInsecure())
	if err != nil {
		fmt.Printf("faild to connect: %v", err)
	}
	defer conn.Close()

	c := message.NewRegisterClient(conn)
	// 调用server的SayHello方法
	r,err := c.RegisterNode(context.Background(), &message.RegisterRequest{
		Ip:"",
		Port:"",
		HostName:"node1"})
	if err != nil {
		fmt.Printf("could not register: %v", err)
	}
	fmt.Printf("Register: %s !\n", r)

	GetIntranetIp()
}
