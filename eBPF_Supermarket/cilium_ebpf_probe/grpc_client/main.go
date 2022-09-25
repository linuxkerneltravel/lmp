package main

import (
	"context"
	"flag"
	"google.golang.org/grpc"
	"log"
	"time"

	pb "lmp/eBPF_Supermarket/cilium_ebpf_probe/proto/greetpb"
)

func mustCreateGrpcClientConn(address string) *grpc.ClientConn {
	conn, err := grpc.Dial(address, grpc.WithInsecure())
	if err != nil {
		log.Fatalf("did not connect: %v", err)
	}
	return conn
}

func connectAndGreet(address, name string, count, sleep_millis int) {
	conn := mustCreateGrpcClientConn(address)
	defer conn.Close()

	c := pb.NewGreeterClient(conn)

	for i := 0; i < count; i++ {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
		defer cancel()
		r, err := c.SayHello(ctx, &pb.HelloRequest{Name: name})
		if err != nil {
			log.Fatalf("could not greet: %v", err)
		}
		log.Printf("Greeting: %s", r.Message)
		time.Sleep(time.Duration(sleep_millis) * time.Millisecond)
	}
}

func main() {
	address := flag.String("address", "10.0.3.130:50051", "Server end point.")
	name := flag.String("name", "world", "The name to greet.")
	count := flag.Int("count", 5, "The number of RPC calls to make.")
	sleep_millis := flag.Int("sleep-millis", 500, "The number of milliseconds to sleep between RPC calls.")
	flag.Parse()
	connectAndGreet(*address, *name, *count, *sleep_millis)
}
