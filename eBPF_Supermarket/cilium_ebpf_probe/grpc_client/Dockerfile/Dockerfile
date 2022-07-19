FROM golang:1.18

WORKDIR /go/src/grpc_client

COPY . .
RUN go mod init GrpcClient 
RUN go env -w GO111MODULE=on && go env -w GOPROXY=https://goproxy.cn,direct
RUN go mod tidy
RUN go env -w GO111MODULE=off
RUN go build main.go

CMD ["./main"]
