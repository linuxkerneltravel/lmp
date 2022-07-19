FROM golang:1.18

WORKDIR /usr/src/http_server

COPY server.go .
RUN go mod init HttpServer 
RUN go env -w GO111MODULE=on && go env -w GOPROXY=https://goproxy.cn,direct
RUN go mod tidy
RUN go build server.go

CMD ["./server"]
