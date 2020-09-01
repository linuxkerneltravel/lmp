package main

import (
	"context"
	"fmt"
	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"
	"lmp-grpc/registerIP/message"
	"net"
	"os"
	"time"
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
	// 调用server的 RegisterNode 方法
	for {
		r,err := c.RegisterNode(context.Background(), &message.RegisterRequest{
			Ip:"",
			Port:"",
			HostName:"node1"})
		if err != nil {
			fmt.Printf("could not register: %v", err)
			time.Sleep(time.Second * 2)
			continue
		}
		fmt.Printf("Register: %s !\n", r)
		conn.Close()
		break
		// If register success, then we close the connect.
	}

	// Then we shart a grpc server
	// Listen to localhost:8972
	lis,err := net.Listen("tcp", ":8080")
	if err != nil {
		fmt.Printf("failed to listen: %v", err)
		return
	}
	// Build rpc server
	s := grpc.NewServer()
	// Register service
	message.RegisterRegisterServer(s, &server{})

	// 在给定的gRPC服务器上注册服务器反射服务
	reflection.Register(s)
	// Serve方法在lis上接受传入连接，为每个连接创建一个ServerTransport和server的goroutine。
	// 该goroutine读取gRPC请求，然后调用已注册的处理程序来响应它们。
	fmt.Println("start...")
	err = s.Serve(lis)
	if err != nil {
		fmt.Printf("failed to serve: %v", err)
		return
	}

	GetIntranetIp()
}
