package main

import (
	"context"
	"fmt"
	"lmp-grpc/registerIP/message"
	"net"
	"sync"

	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"
)

type IPTable struct {
	Ip       string
	Port     string
	HostName string
}


// define globe IPTable
type IPTables struct {
	Tables []IPTable
	mutex sync.Mutex
}

var GlobalIPTable IPTables

func RegisterToTable(m *message.RegisterRequest) error {
	msg := IPTable{
		Ip:m.Ip,
		Port:m.Port,
		HostName:m.HostName,
	}
	GlobalIPTable.mutex.Lock()
	GlobalIPTable.Tables = append(GlobalIPTable.Tables, msg)
	GlobalIPTable.mutex.Unlock()
	return nil
}


type server struct{}

func (s *server)RegisterNode(ctx context.Context, in *message.RegisterRequest) (*message.RegisterReply, error) {

	err := RegisterToTable(in)
	if err != nil {
		fmt.Println("register failed, err:",err)
	}

	for k,v := range GlobalIPTable.Tables {
		fmt.Println(k,v)
	}

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


func main() {
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
}

