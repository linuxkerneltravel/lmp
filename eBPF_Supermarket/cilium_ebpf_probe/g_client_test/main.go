package main

import (
	"context"
	"flag"
	"log"
	"time"

	pb "github.com/lixd/grpc-go-example/features/proto/echo"
	"google.golang.org/grpc"
)

var (
	addr = flag.String("addr", "10.0.3.194:50052", "the address to connect to")
	// 更多配置信息查看官方文档： https://github.com/grpc/grpc/blob/master/doc/service_config.md
	// service这里语法为<package>.<service> package就是proto文件中指定的package，service也是proto文件中指定的 Service Name。
	// method 可以不指定 即当前service下的所以方法都使用该配置。
)

func main() {
	flag.Parse()
	conn, err := grpc.Dial(*addr, grpc.WithInsecure())
	if err != nil {
		log.Fatalf("did not connect: %v", err)
	}
	defer func() {
		if e := conn.Close(); e != nil {
			log.Printf("failed to close connection: %s", e)
		}
	}()

	c := pb.NewEchoClient(conn)

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	reply, err := c.UnaryEcho(ctx, &pb.EchoRequest{Message: "Try and Success"})
	if err != nil {
		log.Fatalf("UnaryEcho error: %v", err)
	}
	log.Printf("UnaryEcho reply: %v", reply)
}
