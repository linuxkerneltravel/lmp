package main

import (
	"context"
	"fmt"
	"lmp-grpc/registerIP/message"
	"net"
	"os"
	"time"

	"github.com/urfave/cli"
	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"
)

type server struct{}

func (s *server)RegisterNode(ctx context.Context, in *message.RegisterRequest) (*message.RegisterReply, error) {
	return &message.RegisterReply{
		State:	"OK",
		Msg:	"register success",
		Code:	0,
		Data:	&message.RegisterRequest{
			Ip:       in.Ip,
			Port:     in.Port,
			HostName: in.HostName,
		},
	},nil
}

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

func checkValid(ctx *cli.Context) error {
	return nil
}

func doBeforeJob(ctx *cli.Context) error {
	if err := checkValid(ctx); err != nil {
		return err
	}
	//todo:load conf file

	//todo:init DB maybe

	return nil
}

func runLMPNode(ctx *cli.Context) error {
	if err := checkValid(ctx); err != nil {
		return err
	}

	//todo:regist to server

	registerToServer()

	// Then we shart a grpc server
	// todo:add conf file
	lis,err := net.Listen("tcp", ":8083")
	if err != nil {
		fmt.Printf("failed to listen: %v", err)
		return err
	}
	// Build rpc server
	s := grpc.NewServer()
	// Register service
	message.RegisterRegisterServer(s, &server{})

	// 在给定的gRPC服务器上注册服务器反射服务
	reflection.Register(s)
	// Serve方法在lis上接受传入连接，为每个连接创建一个ServerTransport和server的goroutine。
	// 该goroutine读取gRPC请求，然后调用已注册的处理程序来响应它们。
	err = s.Serve(lis)
	if err != nil {
		fmt.Printf("failed to serve: %v", err)
		return err
	}
	return nil
}

func registerToServer() {
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
}

func main() {
	app := cli.NewApp()
	app.Name = "LMP-Node"
	app.Usage = ""

	app.Version = "0.0.1"
	app.Before = doBeforeJob
	app.Action = runLMPNode

	if err := app.Run(os.Args); err != nil {
		fmt.Printf("%s\n", err)
		os.Exit(1)
	}
	GetIntranetIp()
}
