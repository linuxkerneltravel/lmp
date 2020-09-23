# Grpc

[TOC]

能看英文尽量看英文：https://grpc.io/docs/languages/go/basics/



### Defining the service

grpc允许定义的四种类型服务

1. Unary RPC，其中客户端向服务器发送单个请求并得到单个响应，就像正常的函数调用一样。
    ```protobuf
    rpc SayHello(HelloRequest) returns (HelloResponse);
    ```
2. Server streaming RPC，其中客户端向服务器发送请求,并获取流以读取一系列消息。 客户端从返回的流中读取，直到没有更多消息为止。 gRPC保证单个RPC调用中的消息排序。
    ```protobuf
    rpc SayHello(HelloRequest) returns (stream HelloResponse);
    ```

3. Client streaming RPC，其中客户端写入一系列消息并将它们发送到服务器，再次使用提供的流。 一旦客户端完成了消息的编写，它将等待服务器读取它们并返回其响应。 同样，gRPC保证单个RPC调用中的消息排序。
    ```protobuf
    rpc SayHello(stream HelloRequest) returns (HelloResponse);
    ```
4. 双向流RPC，其中双方使用读写流发送一系列消息。 这两个流是独立运行的，因此客户机和服务器可以按照它们喜欢的任何顺序进行读和写：例如，服务器可以编写响应之前等待接收所有客户端消息，或者可以交替读取消息然后写入消息，或者其他读写组合。 每个流中的消息顺序被保留。
    ```protobuf
    rpc BidiHello(stream HelloRequest) returns (stream HelloResponse);
    ```





使用gRPC，我们可以在一个.proto文件中定义我们的服务，并以任何gRPC支持的语言生成客户端和服务器，这反过来可以在从大型数据中心内的服务器到您自己的平板电脑的环境中运行-不同语言和环境之间通信的所有复杂性都由gRPC为您处理。 我们还有处理协议缓冲区的所有优点，包括高效的序列化、简单的IDL和易于接口更新。



### Defining the service

在.proto文件中，定义一个服务：(关于protocol buffer的介绍自行google官网)

```protobuf
service RouteGuide {
   ...
}
```

 然后在服务定义中定义rpc方法，指定它们的请求和响应的类型。 gRPC允许定义四种服务方法，在上面有介绍。

 .proto文件还包含服务方法中使用的所有请求和响应类型的协议缓冲区消息类型定义，例如，这里是Point消息类型：

```protobuf
message Point {
  int32 latitude = 1;
  int32 longitude = 2;
}
```



### Generating client and server code

接下来，我们需要从.proto服务定义中生成gRPC客户端和服务器接口。 我们使用 protocol buffer 编译器 `protoc` 与一个特殊的gRPC Go插件。 这与我们在快速启动指南中所做的类似。

例如：

```bash
protoc -I routeguide/ routeguide/route_guide.proto --go_out=plugins=grpc:routeguide
```

在route_guide示例目录下的routeguide目录中生成以下文件：

- `route_guide.pb.go`

这个问阿金包含：

- 所有用于填充、序列化和检索请求和响应消息类型的 protocol buffer code
- 用于客户端调用 `RouteGuide` 中定义的方法的接口类型。
-  一种供服务器实现的接口类型，也包括 `RouteGuide` 中定义的方法。



### Creating the server

 我们的`RouteGuide`有两部分事情要做：

- 实现我们的服务（也就是protocol buffer code中定义的方法）定义生成的服务接口：执行我们服务真正工作。
- 运行一个gRPC服务器来侦听客户端的请求并将它们发送到正确的服务实现。

注意在上面的`RouteGuide`服务定义后，我们生成了go代码，代码里面就已经有了我们需要实现的接口，我们需要定义一个 `routeGuideServer` 结构体并实现这些接口：

```go
type routeGuideServer struct {
        ...
}
...

func (s *routeGuideServer) GetFeature(ctx context.Context, point *pb.Point) (*pb.Feature, error) {
        ...
}
...

func (s *routeGuideServer) ListFeatures(rect *pb.Rectangle, stream pb.RouteGuide_ListFeaturesServer) error {
        ...
}
...

func (s *routeGuideServer) RecordRoute(stream pb.RouteGuide_RecordRouteServer) error {
        ...
}
...

func (s *routeGuideServer) RouteChat(stream pb.RouteGuide_RouteChatServer) error {
        ...
}
...
```



### Simple RPC

`routeGuideServer `实现了我们所有的服务方法。 让我们先看看最简单的类型Get Feature，它只从客户端获取一个Point，并在Feature中从其数据库中返回相应的特征信息：

```go
func (s *routeGuideServer) GetFeature(ctx context.Context, point *pb.Point) (*pb.Feature, error) {
	for _, feature := range s.savedFeatures {
		if proto.Equal(feature.Location, point) {
			return feature, nil
		}
	}
	// No feature was found, return an unnamed feature
	return &pb.Feature{"", point}, nil
}
```

该方法给 `RPC` 和 `客户端Point protocol buffer请求` 发送一个 `context object`。 它返回一个 `Feature` protocol buffer object 和一个 error 信息，`Feature`包含了要返回的信息，在该方法中，我们使用适当的信息填充Feature，然后返回它以及一个零错误，告诉gRPC我们已经完成了对RPC的处理，并且可以将Feature返回给客户端。



### Server-side streaming RPC

现在让我们看看 streaming RPC。 `ListFeatures` 是服务器端流RPC，因此我们需要将多个 `Feature` 发送回客户端。

```go
func (s *routeGuideServer) ListFeatures(rect *pb.Rectangle, stream pb.RouteGuide_ListFeaturesServer) error {
	for _, feature := range s.savedFeatures {
		if inRange(feature.Location, rect) {
			if err := stream.Send(feature); err != nil {
				return err
			}
		}
	}
	return nil
}
```

`ListFeatures` 不是在方法参数中得到简单的请求和响应对象，这次我们得到了一个request object（也就是Rectangle，客户端想要找到多个 `Feature`）和一个特殊的 `RouteGuide_ListFeaturesServer` 对象来写入我们的响应。

在该方法中，我们填充了我们需要返回的尽可能多的Feature对象，并使用它的Send()方法将它们写入`RouteGuide_ListFeaturesServer`。 最后，与我们简单的RPC一样，我们返回一个零错误，告诉gRPC我们已经完成了写入响应。 如果在此调用中发生任何错误，我们将返回一个非nil错误；gRPC层将其转换为要在电线上发送的适当RPC状态。



### Client-side streaming RPC

现在让我们来看看一些更复杂的东西：客户端流方法 `RecordRoute`，我们从客户端获得一条`Point`流，并返回一个带有它们信息的单一 `RouteSummary`。 正如您所看到的，这次方法根本没有请求参数。 相反，它得到一个`RouteGuide_RecordRouteServer` 流，可以使用它来读写消息-使用它的 `Recv()` 方法接收客户端消息，并使用它的 `SendAndClose()` 返回它的单个响应。

```go
func (s *routeGuideServer) RecordRoute(stream pb.RouteGuide_RecordRouteServer) error {
	var pointCount, featureCount, distance int32
	var lastPoint *pb.Point
	startTime := time.Now()
	for {
		point, err := stream.Recv()
		if err == io.EOF {
			endTime := time.Now()
			return stream.SendAndClose(&pb.RouteSummary{
				PointCount:   pointCount,
				FeatureCount: featureCount,
				Distance:     distance,
				ElapsedTime:  int32(endTime.Sub(startTime).Seconds()),
			})
		}
		if err != nil {
			return err
		}
		pointCount++
		for _, feature := range s.savedFeatures {
			if proto.Equal(feature.Location, point) {
				featureCount++
			}
		}
		if lastPoint != nil {
			distance += calcDistance(lastPoint, point)
		}
		lastPoint = point
	}
}
```

在方法主体中，我们使用 `RouteGuide_RecordRouteServer` 的 `Recv()` 方法反复读取客户端对请求对象的请求(在本例中是 `Point`），直到没有更多消息：服务器需要检查每次调用后从 `Read()` 返回的错误。 如果这是零，流仍然是好的，它可以继续阅读；如果是 `io.EOF`。 消息流已经结束，服务器可以返回 `RouteSummary`。 如果它有任何其他值，我们返回错误“原样”，以便它将被gRPC层转换为RPC状态。



### Bidirectional streaming RPC 

```go
func (s *routeGuideServer) RouteChat(stream pb.RouteGuide_RouteChatServer) error {
	for {
		in, err := stream.Recv()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		key := serialize(in.Location)
                ... // look for notes to be sent to client
		for _, note := range s.routeNotes[key] {
			if err := stream.Send(note); err != nil {
				return err
			}
		}
	}
}
```

这一次，我们得到了一个RouteGuide_RouteChatServer流，就像在我们的客户端流例中一样，可以用来读写消息。 然而，这一次我们通过方法的流返回值，而客户端仍然在向它们的消息流写入消息。

这里的读和写语法非常类似于我们的客户端流方法，除了服务器使用流的 `Send()` 方法而不是 `SendAndClose()`方法，因为它编写多个响应。 虽然每一方总是会得到对方的消息，按照他们被写的顺序，客户端和服务器都可以按任何顺序读和写，streams 完全独立地运行。



### Starting the server

一旦我们实现了所有的方法，我们还需要启动gRPC服务器，以便客户端能够实际使用我们的服务。 下面的片段展示了我们如何为我们的 `RouteGuide` 这样做：

```go
flag.Parse()
lis, err := net.Listen("tcp", fmt.Sprintf(":%d", *port))
if err != nil {
        log.Fatalf("failed to listen: %v", err)
}
grpcServer := grpc.NewServer()
pb.RegisterRouteGuideServer(grpcServer, &routeGuideServer{})
... // determine whether to use TLS
grpcServer.Serve(lis)
```

1. 指定要使用lis侦听客户端请求的端口，`lis, err := net.Listen("tcp", fmt.Sprintf(":%d", *port))`.
2. 使用grpc创建gRPC服务器的实例，`grpc.NewServer()`.
3. 用gRPC服务器注册我们的服务实现。
4. 用我们的端口详细信息在服务器上调用 `Serve()` 进行阻塞，直到进程被杀死或 `Stop()` 被调用。



### Creating the client

#### Creating a stub

要调用服务方法，我们首先需要创建一个gRPC通道来与服务器通信。 我们通过将服务器地址和端口号传递给grpc来创建它。`grpc.Dial()`：

```go
conn, err := grpc.Dial(*serverAddr)
if err != nil {
    ...
}
defer conn.Close()
```

可以使用 `DialOptions` 在grpc中设置Auth凭据(例如，TLS、GCE凭据、JWT凭据)，当然是有需求的时候，但是，这里我们不需要。

一旦设置了gRPC通道，我们就需要一个 `客户端 stub` 来执行RPC。 我们使用我们从.proto生成的PB包中提供的`NewRouteGuideClient` 客户端方法来获得这个。

```go
client := pb.NewRouteGuideClient(conn)
```



#### Calling service methods

现在让我们看看我们如何调用我们的服务方法。 请注意，在gRPC-Go中，RPC以阻塞/同步模式操作，这意味着RPC调用等待服务器响应，并且将返回响应或错误。

##### Simple RPC

simple RPC就和调用表本地的函数一样：

```go
feature, err := client.GetFeature(context.Background(), &pb.Point{409146138, -746188906})
if err != nil {
        ...
}
```

 我们在前面得到的 `stub` 上调用方法。 在我们的方法参数中，我们创建并填充一个protocal buffer object(在我们的例子中是Point)。 我们还传递了一个上下文。 `context.Context`，它允许我们在必要时改变RPC的行为，例如传输中的超时/取消RPC。 如果调用不返回错误，那么我们可以从服务器从第一个返回值读取响应信息。



##### Server-side streaming RPC

这里我们调用服务器端流方法 `ListFeatures`，它返回一个由 `Feature `组成的流。 和 Create the serve中的一些内容可能看起来非常熟悉——streaming RPC以类似的方式在两边实现。

```go
rect := &pb.Rectangle{ ... }  // initialize a pb.Rectangle
stream, err := client.ListFeatures(context.Background(), rect)
if err != nil {
    ...
}
for {
    feature, err := stream.Recv()
    if err == io.EOF {
        break
    }
    if err != nil {
        log.Fatalf("%v.ListFeatures(_) = _, %v", client, err)
    }
    log.Println(feature)
}
```

与 simple RPC 一样，我们传递方法、上下文和请求。 但是，我们不是将响应对象返回，而是返回一个RouteGuide_ListFeaturesClient实例。 客户端可以使用RouteGuide_ListFeaturesClient流来读取服务器的响应。

我们使用 `RouteGuide_ListFeaturesClient` 的 `Recv()` 方法反复读取服务器对响应协议缓冲区对象(在这种情况下是Feature)的响应，直到没有更多消息：客户端需要检查每次调用后从Recv()返回的错误错误错误。 如果是零，流仍然是好的，它可以继续阅读；如果是IO。 然后消息流就结束了；否则就会有一个RPC错误，它是通过错误传递的。



##### Client-side streaming RPC

客户端流方法Record Route与服务器端方法相似，只是我们只传递方法一个上下文，然后得到一个RouteGuide_RecordRouteClient流回来，我们可以用它来写和读消息。

```go
// Create a random number of random points
r := rand.New(rand.NewSource(time.Now().UnixNano()))
pointCount := int(r.Int31n(100)) + 2 // Traverse at least two points
var points []*pb.Point
for i := 0; i < pointCount; i++ {
	points = append(points, randomPoint(r))
}
log.Printf("Traversing %d points.", len(points))
stream, err := client.RecordRoute(context.Background())
if err != nil {
	log.Fatalf("%v.RecordRoute(_) = _, %v", client, err)
}
for _, point := range points {
	if err := stream.Send(point); err != nil {
		if err == io.EOF {
			break
		}
		log.Fatalf("%v.Send(%v) = %v", stream, point, err)
	}
}
reply, err := stream.CloseAndRecv()
if err != nil {
	log.Fatalf("%v.CloseAndRecv() got error %v, want %v", stream, err, nil)
}
log.Printf("Route summary: %v", reply)
```

`RouteGuide_RecordRouteClient` 有一种 `Send()` 方法，我们可以使用它向服务器发送请求。 一旦我们完成了使用 `Send()` 将客户端的请求写入流，我们需要调用流上的 `CloseAndRecv()`，让gRPC知道我们已经完成了写入，并期望收到响应。 我们从 `CloseAndRecv()` 返回的错误中获得RPC状态。 如果状态为零，则 `CloseAndRecv()` 的第一个返回值将是有效的服务器响应。



##### Bidirectional streaming RPC

最后，让我们看看我们的双向流RPC `RouteChat()`。 与Record Route的情况一样，我们只传递一个上下文对象的方法，并返回一个流，我们可以使用它来写和读消息。 然而，这一次我们通过方法的流返回值，而服务器仍然在向它们的消息流写入消息。

```go
stream, err := client.RouteChat(context.Background())
waitc := make(chan struct{})
go func() {
	for {
		in, err := stream.Recv()
		if err == io.EOF {
			// read done.
			close(waitc)
			return
		}
		if err != nil {
			log.Fatalf("Failed to receive a note : %v", err)
		}
		log.Printf("Got message %s at point(%d, %d)", in.Message, in.Location.Latitude, in.Location.Longitude)
	}
}()
for _, note := range notes {
	if err := stream.Send(note); err != nil {
		log.Fatalf("Failed to send a note: %v", err)
	}
}
stream.CloseSend()
<-waitc
```

这里的 reading 和 writing 语法非常类似于我们的客户端流方法，除非我们在完成调用后使用流的CloseSend()方法。 虽然每一方总是会得到对方的消息，按照他们被写的顺序，客户端和服务器都可以按任何顺序读和写-流完全独立地运行。















