package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"sync"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/lixd/grpc-go-example/features/proto/echo"
)

var port = flag.Int("port", 50052, "port number")

type failingServer struct {
	pb.UnimplementedEchoServer
	mu sync.Mutex

	reqCounter uint
	reqModulo  uint
}

// maybeFailRequest 手动模拟请求失败 一共请求n次，前n-1次都返回失败，最后一次返回成功。
func (s *failingServer) maybeFailRequest() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.reqCounter++
	if (s.reqModulo > 0) && (s.reqCounter%s.reqModulo == 0) {
		return nil
	}

	return status.Errorf(codes.Unavailable, "maybeFailRequest: failing it")
}

func (s *failingServer) UnaryEcho(ctx context.Context, req *pb.EchoRequest) (*pb.EchoResponse, error) {
	if err := s.maybeFailRequest(); err != nil {
		log.Println("request failed count:", s.reqCounter)
		return nil, err
	}

	log.Println("request succeeded count:", s.reqCounter)
	return &pb.EchoResponse{Message: req.Message}, nil
}

func main() {
	flag.Parse()

	address := fmt.Sprintf(":%v", *port)
	lis, err := net.Listen("tcp", address)
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}
	fmt.Println("listen on address", address)

	s := grpc.NewServer()

	// 指定第4次请求才返回成功，用于测试 gRPC 的 retry 功能。
	failingservice := &failingServer{
		reqModulo: 4,
	}

	pb.RegisterEchoServer(s, failingservice)
	if err := s.Serve(lis); err != nil {
		log.Fatalf("failed to serve: %v", err)
	}
}
