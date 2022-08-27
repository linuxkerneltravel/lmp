package main

import (
	"context"
	"flag"
	"log"
	"net"
	"strconv"

	"google.golang.org/grpc"

	pb "lmp/eBPF_Supermarket/cilium_ebpf_probe/proto/greetpb"
)

type server struct{}
type test struct{}

func (s *server) SayHello(ctx context.Context, in *pb.HelloRequest) (*pb.HelloReply, error) {
	log.Printf(in.Name)
	return &pb.HelloReply{Message: "Hello " + in.Name}, nil
}
func (t *test) aestfunc(a int, b int) int {
	log.Printf("yes")
	return a + b
}
func main() {
	port := flag.Int("port", 50052, "The port to listen.")
	flag.Parse()

	log.Printf("Starting http server on port: %d", *port)
	lis, err := net.Listen("tcp", ":"+strconv.Itoa(*port))
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}

	s := grpc.NewServer()

	log.Printf("Launching unary server")
	pb.RegisterGreeterServer(s, &server{})

	t := test{}
	t.aestfunc(3, 4)
	if err := s.Serve(lis); err != nil {
		log.Fatalf("failed to serve: %v", err)
	}
}
